# EXECUTE.md

TASK: Execute as many planned tasks as possible from the target project's backlog in strict priority order: audit findings first, then planned steps, then roadmap items.

## Execution Mode

**Autonomous action** — implement tasks fully, validate each with tests and diff, then continue to the next task until a stopping condition is met.

This prompt operates on a **third-party C# project**, not on any tooling infrastructure. Every decision must serve the target project's own stated goals and conventions.

---

## Prerequisites

Verify required tools are installed:

```bash
# .NET SDK (required)
dotnet --version  # Should be 6.0 or higher

# Optional but recommended tools
dotnet tool install -g dotnet-format
dotnet tool install -g dotnet-outdated-tool
dotnet tool install -g coverlet.console

# Code metrics tool (install if needed)
dotnet tool install -g dotnet-code-metrics
```

---

## Workflow

### Phase 0: Understand the Target Project's Goals

Before executing any task, build deep context on the project you are working in:

1. **Read the project README thoroughly** — extract every stated goal, feature claim, capability promise, performance target, and audience statement. These are the **acceptance criteria** for your work.

2. **Examine solution structure:**
   - Inspect `*.sln` and `*.csproj` files for:
     - Target framework(s) (net8.0, net6.0, netstandard2.1, etc.)
     - NuGet package references and versions
     - Project dependencies and structure
     - Language version and nullable reference types configuration
   - Check `Directory.Build.props` and `.editorconfig` for project-wide settings

3. **Scan existing source files** to identify the project's code style:
   - Error handling patterns (exceptions vs result types)
   - Naming conventions (PascalCase, async suffix conventions)
   - Test strategy (xUnit, NUnit, MSTest)
   - Preferred idioms (LINQ usage, async/await patterns, null handling)

4. **Note any CI configuration:**
   - `.github/workflows/*.yml`
   - `azure-pipelines.yml`
   - `.gitlab-ci.yml`
   - Look for quality gates: build warnings as errors, code coverage thresholds, static analysis

5. **Identify critical paths:**
   - Public API surfaces
   - Core business logic classes
   - Database access layers
   - Changes to these require extra care and thorough testing

---

### Phase 1: Online Research

Use web search to build context before executing:

1. Search for the project on GitHub — read open issues and recent PRs related to planned tasks
2. Research any NuGet packages or APIs involved in upcoming tasks for:
   - Known issues or CVEs
   - Breaking changes in newer versions
   - Deprecation notices
3. Look up implementation best practices relevant to the planned changes
4. Check Microsoft docs for framework-specific guidance on affected features

Keep research brief (≤10 minutes). Record only findings that directly affect how you implement or validate the tasks.

---

### Phase 2: Session Baseline

Capture a single baseline at the start of the session. This baseline persists across all tasks and is used for the final session-level diff.

```bash
# Create working directory
mkdir -p tmp

# Capture build warnings
dotnet build --no-restore /warnaserror 2>&1 | tee tmp/baseline-build.txt || true

# Capture test results
dotnet test --no-build --logger "trx;LogFileName=baseline-tests.trx" 2>&1 | tee tmp/baseline-test.txt

# Capture code coverage (if coverlet is available)
dotnet test --no-build --collect:"XPlat Code Coverage" --results-directory tmp/baseline-coverage 2>&1 || true

# Capture code metrics
dotnet-code-metrics analyze . --output tmp/baseline-metrics.json 2>&1 || \
  echo "Code metrics tool not available - skipping" > tmp/baseline-metrics.json

# Capture format violations
dotnet format --verify-no-changes --verbosity diagnostic 2>&1 | tee tmp/baseline-format.txt || true

# Count nullable warnings
grep -c "CS86[0-9][0-9]" tmp/baseline-build.txt > tmp/baseline-nullable-count.txt 2>/dev/null || echo "0" > tmp/baseline-nullable-count.txt

# Store baseline NuGet vulnerabilities
dotnet list package --vulnerable --include-transitive 2>&1 | tee tmp/baseline-security.txt
```

**Do NOT delete these baseline files** until the final session validation is complete.

---

### Phase 3: Task Execution Loop

Repeat the following cycle for each task until a **stopping condition** is met:

#### 3a. Select Task

**Strict file priority order, NO EXCEPTIONS:**

1. **First**: `AUDIT.md` (or any `*AUDIT*.md`). Take the first unchecked `- [ ]` item.
2. **Second**: `PLAN.md`. Take the first incomplete step.
3. **Third**: `ROADMAP.md`. Take the first incomplete item.

**Do NOT skip priority levels. Do NOT reorder.**

If the next task has logical sub-items, execute the entire group as one unit.

#### 3b. Implement

Match the project's existing conventions and advance its stated goals:

**Code Style Conformance:**
- Mirror the codebase's error handling style:
  - Exception-based error handling vs Result<T> pattern
  - Custom exception types vs framework exceptions
  - Exception wrapping and context preservation
- Follow the project's naming conventions:
  - Async method naming (`*Async` suffix)
  - Interface naming (`I*` prefix)
  - Private field naming (`_camelCase` vs `camelCase`)
- Respect established patterns:
  - Dependency injection registration style
  - Configuration pattern (Options pattern, IConfiguration)
  - Logging approach (ILogger, structured logging)

**Structural Respect:**
- Preserve all existing public API signatures
- Maintain project's folder/namespace structure
- Follow existing test organization patterns
- Respect project's async/await usage patterns

**Quality Targets (calibrate to project baseline):**
- Function length: ≤50 lines (adjust based on project norms)
- Cyclomatic complexity: ≤10 (measure via mental count of branches)
- Test coverage: maintain or improve existing percentage
- Nullable reference warnings: do not introduce new CS86xx warnings

**Goal Alignment:**
- Verify the change serves the project's stated goals
- Do not introduce code that contradicts what the project claims to do
- Cross-reference with README feature claims

#### 3c. Per-Task Validation

After each task, confirm ALL of the following:

```bash
# Clean build
dotnet clean
dotnet restore

# Build succeeds
dotnet build --no-restore
# Exit code must be 0

# Tests pass
dotnet test --no-build
# Exit code must be 0

# No new warnings introduced
dotnet build --no-restore 2>&1 | tee tmp/current-build.txt
# Compare warning count to baseline - must not increase

# Format check (if project uses dotnet-format)
dotnet format --verify-no-changes || echo "Format issues detected"

# No new nullable warnings
grep -c "CS86[0-9][0-9]" tmp/current-build.txt > tmp/current-nullable-count.txt 2>/dev/null || echo "0" > tmp/current-nullable-count.txt
# Count must be ≤ baseline count
```

**Validation Rules:**

If per-task validation fails:
1. Attempt to fix the issue immediately
2. If the fix requires:
   - Modifying files outside the task's scope, OR
   - Adding >20 lines of unplanned code, OR
   - Changing public API signatures
   
   Then: **Revert the task changes**, note the blocker in the task log, and proceed to the next task.

**Quality Gate:**
- The change advances (or does not regress) the project's stated goals
- No new build warnings introduced
- No new nullable reference warnings
- All tests pass
- Code compiles successfully

#### 3d. Mark Completion

1. Check off completed items (`- [x]`) in the source file
2. Record the task in the session log for the final output
3. Commit changes with descriptive message referencing the source file and task

---

### Stopping Conditions

Stop the loop when **any** of the following is true:

1. **Backlog exhausted**: All items in `AUDIT.md` and `PLAN.md` have been completed and both files have been deleted (see Task Completion Rules).

2. **Unrecoverable regression**: A task causes:
   - Test failures that cannot be resolved within task scope
   - Build failures
   - Clear regression of the project's stated goals
   
   AND the issue cannot be resolved quickly — revert it, log it, and stop.

3. **Context boundary**: The next task requires:
   - Modifying files in a top-level namespace not yet touched in this session, AND
   - Involves a subsystem with different domain concerns
   
   Examples: switching from data processing to HTTP controllers, or from core logic to deployment configuration.

4. **High-risk threshold**: The next task involves:
   - Changes to public API signatures
   - Database schema modifications
   - Breaking changes to NuGet package references
   - Modifications to authentication/authorization logic
   - Changes affecting security-critical code
   
   These warrant isolated review.

**Decision Rule**: When no stopping condition is met and you are unsure whether to continue, execute one more task rather than stopping early. Prefer completing more work per session.

---

### Phase 4: Session Validation

After the loop ends, perform a final session-level validation against the original baseline:

```bash
# Capture final state
dotnet build --no-restore /warnaserror 2>&1 | tee tmp/final-build.txt || true
dotnet test --no-build --logger "trx;LogFileName=final-tests.trx" 2>&1 | tee tmp/final-test.txt
dotnet test --no-build --collect:"XPlat Code Coverage" --results-directory tmp/final-coverage 2>&1 || true
dotnet-code-metrics analyze . --output tmp/final-metrics.json 2>&1 || echo "{}" > tmp/final-metrics.json
dotnet format --verify-no-changes --verbosity diagnostic 2>&1 | tee tmp/final-format.txt || true

# Compare nullable warnings
grep -c "CS86[0-9][0-9]" tmp/final-build.txt > tmp/final-nullable-count.txt 2>/dev/null || echo "0" > tmp/final-nullable-count.txt

# Security audit
dotnet list package --vulnerable --include-transitive 2>&1 | tee tmp/final-security.txt

# Generate diff report
echo "=== BUILD WARNINGS DIFF ===" > tmp/session-diff.txt
echo "Baseline warnings: $(wc -l < tmp/baseline-build.txt)" >> tmp/session-diff.txt
echo "Final warnings: $(wc -l < tmp/final-build.txt)" >> tmp/session-diff.txt

echo "" >> tmp/session-diff.txt
echo "=== NULLABLE WARNINGS DIFF ===" >> tmp/session-diff.txt
echo "Baseline CS86xx warnings: $(cat tmp/baseline-nullable-count.txt)" >> tmp/session-diff.txt
echo "Final CS86xx warnings: $(cat tmp/final-nullable-count.txt)" >> tmp/session-diff.txt

echo "" >> tmp/session-diff.txt
echo "=== TEST RESULTS DIFF ===" >> tmp/session-diff.txt
dotnet test --no-build --list-tests 2>&1 | wc -l > tmp/final-test-count.txt
echo "Tests found: $(cat tmp/final-test-count.txt)" >> tmp/session-diff.txt

# Compare code coverage if available
if [ -d tmp/baseline-coverage ] && [ -d tmp/final-coverage ]; then
    echo "" >> tmp/session-diff.txt
    echo "=== COVERAGE DIFF ===" >> tmp/session-diff.txt
    echo "Baseline coverage reports in tmp/baseline-coverage" >> tmp/session-diff.txt
    echo "Final coverage reports in tmp/final-coverage" >> tmp/session-diff.txt
fi

# Display diff
cat tmp/session-diff.txt
```

**Confirm ALL of the following:**

| Criterion | Check |
|-----------|-------|
| No metric regressions | Session diff shows zero regressions in build warnings, nullable warnings, test count |
| Tests pass | `dotnet test --no-build` exits 0 |
| Build succeeds | `dotnet build --no-restore` exits 0 |
| Nullable warnings stable/reduced | Final CS86xx count ≤ baseline count |
| Security posture stable | No new high/critical vulnerabilities introduced |
| At least one task completed | Session completed ≥1 task successfully |
| Compliance with stated goals | Changes advance the project's own stated goals (README) and fulfill the intent documented in AUDIT.md / PLAN.md / ROADMAP.md |

**Cleanup after successful validation:**
```bash
rm -rf tmp/baseline-* tmp/final-* tmp/current-* tmp/session-diff.txt
```

---

## Success Criteria

| Criterion | Check |
|-----------|-------|
| **No metric regressions** | Session diff shows zero regressions across all metrics |
| **Tests pass** | `dotnet test --no-build` exits 0 |
| **Build succeeds** | `dotnet build --no-restore` exits 0 |
| **At least one task completed** | Session completed ≥1 task successfully |
| **Compliance with stated goals** | Changes advance the project's own stated goals (README) and fulfill the intent documented in AUDIT.md / PLAN.md / ROADMAP.md |
| **No new warnings** | Build warning count does not increase |
| **Nullable warnings stable** | CS86xx warning count does not increase |

---

## Default Thresholds

Calibrate to project baseline:

- **Max function length**: 50 lines (C# methods tend toward longer than Go functions)
- **Max cyclomatic complexity**: 10
- **Min test coverage**: 70% (or match project baseline)
- **Zero regression tolerance** on build warnings
- **Zero new nullable warnings** (CS8600-CS8899)
- **Zero new high/critical security vulnerabilities**

---

## Priority Rules

The task priority order is **absolute and non-negotiable**:

1. **AUDIT.md** — bug fixes and critical findings always come first
2. **PLAN.md** — implementation plan items come second
3. **ROADMAP.md** — strategic improvements come last

**Execute what is next, not what seems most interesting or impactful.**

---

## Task Completion Rules

1. **If a finding is already resolved** (code matches expectation), check it off and move to the next task in the loop.

2. **If a task requires information not available**, note the blocker and skip to the next task in the loop.

3. **After completing all items in `AUDIT.md`**, delete it to signal completion.

4. **After completing all items in `PLAN.md`**, delete it to signal completion.

5. **CRITICAL**: Any automated development loop halts only when both `AUDIT.md` and `PLAN.md` are deleted. Failure to delete these files upon completion will cause the loop to run indefinitely.

---

## C#-Specific Implementation Guidelines

### Error Handling

**Match the project's existing pattern:**

- **Exception-based** (most common in C#):
  ```csharp
  // Follow project's exception hierarchy
  throw new ValidationException("User input invalid", innerException);
  ```

- **Result<T> pattern** (if project uses it):
  ```csharp
  return Result<User>.Failure("User not found");
  ```

- **Nullable reference types** (if enabled):
  ```csharp
  public User? FindUser(string id) // ? indicates nullable return
  ```

### Async/Await Patterns

**Respect project conventions:**

```csharp
// Method naming
public async Task<User> GetUserAsync(string id, CancellationToken cancellationToken = default)
{
    // Always pass cancellation tokens through
    return await _repository.GetAsync(id, cancellationToken);
}

// ConfigureAwait in library code (check project usage)
var result = await SomeOperationAsync().ConfigureAwait(false);
```

### Dependency Injection

**Follow project's DI registration style:**

```csharp
// Typical ASP.NET Core pattern
services.AddScoped<IUserService, UserService>();
services.AddSingleton<ICacheService, CacheService>();

// Or more complex registration
services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(configuration.GetConnectionString("Default")));
```

### Nullable Reference Types

**When enabled (check .csproj for `<Nullable>enable</Nullable>`):**

- Do not introduce new CS8600-CS8899 warnings
- Use `?` suffix for nullable types: `string?`, `User?`
- Use null-forgiving operator `!` only when absolutely necessary and with justification
- Prefer null checks and early returns

```csharp
public User GetUser(string? id)
{
    if (id is null) throw new ArgumentNullException(nameof(id));
    // ... safe to use id here
}
```

### Test Patterns

**Match project's test framework:**

```csharp
// xUnit (most common)
[Fact]
public void UserService_CreateUser_ThrowsWhenEmailInvalid()
{
    // Arrange
    var service = new UserService();
    
    // Act & Assert
    Assert.Throws<ValidationException>(() => 
        service.CreateUser("invalid-email"));
}

// NUnit
[Test]
public void UserService_CreateUser_ThrowsWhenEmailInvalid()
{
    Assert.Throws<ValidationException>(() => 
        service.CreateUser("invalid-email"));
}
```

### Common Warning Categories

When counting/comparing warnings:

- **CS8600-CS8899**: Nullable reference warnings (track separately)
- **CS0618**: Obsolete API usage (moderate priority)
- **CS1591**: Missing XML documentation (low priority unless project enforces)
- **CS0219**: Unused variable (cleanup opportunity)

---

## Output Format

```markdown
## Session Summary
Tasks completed: [N]
Tasks skipped: [N] (with reasons)
Tasks reverted: [N] (with reasons)

## Task Log

### Task 1
Source: [AUDIT.md | PLAN.md | ROADMAP.md]
Task: [description]
Files modified: [list]
Build: PASS
Tests: PASS
Warnings: No new warnings
Result: COMPLETED

### Task 2
Source: [AUDIT.md | PLAN.md | ROADMAP.md]
Task: [description]
Files modified: [list]
Build: PASS
Tests: PASS
Warnings: No new warnings
Result: COMPLETED

### Task 3
Source: [AUDIT.md | PLAN.md | ROADMAP.md]
Task: [description]
Files modified: [list]
Build: FAIL - Introduced 3 new CS8602 warnings in UserService.cs
Tests: N/A
Result: REVERTED
Reason: Introduced nullable reference warnings outside task scope

...

## Session Diff

### Build Warnings
- Baseline: 42 warnings
- Final: 42 warnings
- Change: 0 (no regression)

### Nullable Warnings (CS86xx)
- Baseline: 15 warnings
- Final: 12 warnings
- Change: -3 (improvement)

### Test Results
- Total tests: 247
- Passed: 247
- Failed: 0
- Skipped: 0

### Code Coverage
- Baseline: 73.2% line coverage
- Final: 74.8% line coverage
- Change: +1.6%

### Security
- No new vulnerabilities introduced
- No high/critical vulnerabilities present

## Stop Reason
[backlog exhausted | unrecoverable regression | context boundary | high-risk threshold]

## Compliance Assessment
Changes advance the following stated goals from README:
- ✅ "Provides thread-safe caching" - Added concurrent access tests, resolved nullable warnings in CacheManager
- ✅ "High-performance data processing" - Maintained benchmark performance within 5% of baseline
- ✅ "Well-documented public API" - Added XML docs to 8 public methods

No regressions detected against stated goals.
```

---

## Tiebreaker

Always take the **first unchecked item** in the current priority file. Never skip ahead.

---

## Forbidden Actions

❌ Do NOT modify CI/CD pipeline files unless explicitly required by a task  
❌ Do NOT change public API signatures without explicit task authorization  
❌ Do NOT introduce breaking changes to NuGet package references  
❌ Do NOT modify database migration files unless explicitly required  
❌ Do NOT add new third-party dependencies without task authorization  
❌ Do NOT change framework target versions (e.g., net6.0 → net8.0) without explicit task  
❌ Do NOT disable build warnings or nullable warnings to pass validation  
❌ Do NOT skip tests to pass validation  

---

## Notes for Automation

If implementing this in an automated loop (e.g., `loop.sh`):

1. The loop MUST check for existence of `AUDIT.md` and `PLAN.md`
2. The loop MUST terminate when both files are deleted
3. Each iteration should:
   - Run this prompt
   - Commit changes if validation passes
   - Check stopping conditions
   - Continue or halt accordingly

Example shell pseudocode:
```bash
#!/bin/bash
while [ -f "AUDIT.md" ] || [ -f "PLAN.md" ]; do
    # Run LLM with EXECUTE.md prompt
    # Check exit code
    # If stopping condition reached, break
    sleep 1
done
echo "Backlog exhausted - loop complete"
```
