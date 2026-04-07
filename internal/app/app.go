package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"secure-code-retrieval-mcp/internal/audit"
	"secure-code-retrieval-mcp/internal/config"
	ghconnector "secure-code-retrieval-mcp/internal/connectors/github"
	glconnector "secure-code-retrieval-mcp/internal/connectors/gitlab"
	"secure-code-retrieval-mcp/internal/gateway"
	"secure-code-retrieval-mcp/internal/mcp"
	"secure-code-retrieval-mcp/internal/policy"
	"secure-code-retrieval-mcp/internal/sanitize"
	postgresstore "secure-code-retrieval-mcp/internal/storage/postgres"
)

type Application struct {
	logger     *slog.Logger
	httpServer *http.Server
	mcpServer  *mcp.Server
}

func New(cfg config.Config, logger *slog.Logger) (*Application, error) {
	repository, err := postgresstore.NewAuditRepository(cfg.Database, logger)
	if err != nil {
		return nil, err
	}
	auditor := audit.NewService(repository)
	providerFactory := sanitize.NewProviderFactory(cfg.Models, cfg.Network.Proxy, logger)
	sanitizer := sanitize.NewService(providerFactory, logger)
	policyEngine, err := policy.NewEngine(cfg.Policies)
	if err != nil {
		return nil, err
	}
	githubConnector, err := ghconnector.New(cfg.Connectors.GitHub, cfg.Network.Proxy, logger)
	if err != nil {
		return nil, err
	}
	gitlabConnector, err := glconnector.New(cfg.Connectors.GitLab, cfg.Network.Proxy, logger)
	if err != nil {
		return nil, err
	}
	svc := gateway.NewService(gateway.Dependencies{
		Logger:    logger,
		Timeout:   cfg.Runtime.RequestTimeout,
		GitHub:    githubConnector,
		GitLab:    gitlabConnector,
		Policy:    policyEngine,
		Sanitizer: sanitizer,
		Auditor:   auditor,
	})
	httpServer := &http.Server{
		Addr:              cfg.Runtime.HTTPAddress,
		Handler:           NewHTTPHandler(svc, logger),
		ReadHeaderTimeout: 5 * time.Second,
	}
	mcpServer := mcp.NewServer(svc, logger)
	return &Application{logger: logger, httpServer: httpServer, mcpServer: mcpServer}, nil
}

func (a *Application) Run(ctx context.Context) error {
	httpErrCh := make(chan error, 1)
	go func() {
		a.logger.Info("http server listening", "addr", a.httpServer.Addr)
		err := a.httpServer.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			httpErrCh <- err
			return
		}
		httpErrCh <- nil
	}()

	mcpErrCh := make(chan error, 1)
	go func() {
		a.logger.Info("mcp server starting on stdio")
		mcpErrCh <- a.mcpServer.Serve(ctx)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = a.httpServer.Shutdown(shutdownCtx)
		return nil
	case err := <-httpErrCh:
		return err
	case err := <-mcpErrCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = a.httpServer.Shutdown(shutdownCtx)
		return nil
	}
}
