//go:build !cli

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// CRUD-to-command guard parity inventory.
//
// An approved command runs its own SQL, so every guard the generic CRUD write
// pipeline applies has to be either re-applied on the command path or exempt for
// a stated reason. This test reads the source: it collects every package-level
// function the CRUD write entry points call and fails when one is not classified
// below, when a classification is stale, or when a counterpart the command path
// relies on is no longer called from the command write path. A new CRUD guard
// therefore cannot land without a decision for approved commands.

// crudWritePipeline is every generic CRUD write entry point and the shared
// mutation helpers they run.
var crudWritePipeline = []string{
	"requireAPIAuth", "requireAPIAuthForOp", "handleCreate", "handleUpdate", "handleRestore", "handleDelete", "handleSingletonUpdate",
	"handleBatchCreate", "handleBatchUpdate", "handleBatchDelete", "handleStreamingIngest",
	"executeCRUDTransaction", "txInsert", "txUpdate", "txUpdateMode", "txDelete", "validateTxMutation",
	"applyCanonicalUpdateTxContextMode", "handleTransition", "cascadeSoftDelete",
	"txInsertWithPlan", "newInsertPlan", "txDeleteRow", "validateTxMutationRules", "protectedUpdateFields",
	"cascadeSoftDeleteChildren", "transitionEffectsTx",
}

// commandWritePathFiles hold the approved-command prepare/approve/commit path.
var commandWritePathFiles = []string{
	"flows_command.go", "flows_command_runtime.go", "app_mcp_command_provider.go", "app_mcp_command_hooks.go",
	"app_mcp_command_effects.go", "app_mcp_command_exposure.go", "app_mcp_command_authority.go",
	"app_mcp_command_dependencies.go", "app_mcp_command_declaration.go",
}

type commandParityRule struct {
	// counterparts must each be called from commandWritePathFiles.
	counterparts []string
	// why says how the command path covers the guard, or why it is exempt.
	why string
}

const (
	commandParityAuthored   = "author-scoped: a command's row, owner, tenant and membership scope is its own reviewed SQL bound to user.id/user.group_id; dependencies re-verify the prepared rows at commit"
	commandParityPlumbing   = "plumbing: request parsing, schema lookup or response shaping with no guard of its own"
	commandParityPipeline   = "pipeline step: its own calls are inventoried as part of crudWritePipeline"
	commandParityOwned      = "ownership constrains generic CRUD only (api(at:\"scoping\") command_owned_fields); commands may write owned columns"
	commandParityMembership = "the implicit tenant-admin rule on the groups membership table constrains generic CRUD only; a command, like a flow, is the app's own reviewed way to manage members and names who may run it"
)

var crudGuardCommandParity = map[string]commandParityRule{
	// Enforced on the command path.
	"Broadcast":                      {[]string{"appMCPCommandBroadcasts", "appMCPBroadcastCommitted"}, "realtime events after a confirmed commit only"},
	"broadcastHookRefreshes":         {[]string{"canonicalHookRefreshScopes"}, "hook-written tables refresh after a confirmed commit"},
	"EnforceCRUDAccess":              {[]string{"appMCPCommandScopes"}, "the declared write permissions must be held by the grant and the actor's current role"},
	"checkScope":                     {[]string{"appMCPCommandScopes"}, "the declared write permissions must be held by the grant and the actor's current role"},
	"fireBeforeHooksWith":            {[]string{"fireBeforeHooksRows"}, "before-hooks run on each probed row inside the command transaction"},
	"fireBeforeHooksRows":            {[]string{"fireBeforeHooksRows"}, "before-hooks run on each probed row inside the command transaction"},
	"submittedHookRow":               {[]string{"submittedHookRow"}, "an update's hook SQL placeholders resolve against the changed columns, as for PATCH"},
	"enqueueRowEffectsTx":            {[]string{"fireAfterHooksTx", "enqueueWebhookSubscriptionsTx"}, "insert/delete hook jobs and subscriptions are queued in the write transaction; commands queue theirs in the command transaction"},
	"fireAfterHooksTx":               {[]string{"fireAfterHooksTx"}, "on-hooks run in the command transaction; delivery actions are queued effects"},
	"fireCascadedDeleteEvents":       {[]string{"appMCPEnqueueEventFlows", "appMCPCommandBroadcasts"}, "a cascade's event flows and broadcasts after commit; commands do not cascade (author-scoped apply SQL)"},
	"enqueueWebhookSubscriptionsTx":  {[]string{"enqueueWebhookSubscriptionsTx"}, "subscriptions are queued in the command transaction with the stripped payload row"},
	"FireFlowsForEvent":              {[]string{"appMCPEnqueueEventFlows", "flowEventRowTaint"}, "event flows are queued effects that keep the row's request taint"},
	"materializeValidatorDefaults":   {[]string{"ValidateCrossField"}, "approved commands validate complete SQLite probe rows, which already contain database defaults; this helper prepares omitted generic CRUD fields before their insert"},
	"materializeUUIDDefaults":        {nil, "native CRUD repairs omitted legacy Prisma UUID defaults; reviewed command SQL keeps its explicit values and physical defaults"},
	"prismaUUIDDefaultColumns":       {nil, "selects only published Prisma uuid() columns with a known generated physical default for native CRUD compatibility; command SQL is explicit"},
	"ValidateCrossField":             {[]string{"ValidateCrossField"}, "cross-field validators run on each probed insert/update row"},
	"fireHookListTxMode":             {[]string{"appMCPEnqueueTransitionHooks", "fireAfterHooksTx"}, "commands record transition hooks as durable effects inside the command transaction; ordinary after-hooks share the transactional SQL/job helper (its deferred mode serves system timeouts, which have no command)"},
	"afterHooksFor":                  {[]string{"fireAfterHooksTx"}, "selects the table's on-hooks, as fireAfterHooksTx does for commands"},
	"transitionEffectsTx":            {nil, commandParityPipeline},
	"workflowCreateInitial":          {[]string{"workflowCreateStateRefused"}, "CRUD writes the initial state; a command's own SQL cannot be rewritten, so its inserted row is refused unless it starts there"},
	"withWorkflowInitial":            {[]string{"workflowCreateStateRefused"}, "CRUD writes the initial state; a command's own SQL cannot be rewritten, so its inserted row is refused unless it starts there"},
	"workflowCreateStateRefused":     {[]string{"workflowCreateStateRefused"}, "new rows must start in the workflow's initial state"},
	"workflowProtectedFields":        {[]string{"appMCPValidateWorkflowTransition"}, "a state change must be a declared transition"},
	"hasWorkflowRole":                {[]string{"appMCPCommandHasWorkflowRole"}, "transition role guards, compared as the CRUD route compares them"},
	"workflowRoleRequired":           {[]string{"workflowRoleRequired"}, "a refused transition names the roles it needs, as on the CRUD route"},
	"whenHolds":                      {[]string{"evaluateWhen"}, "transition and hook when: conditions"},
	"transitionEventRow":             {[]string{"transitionEventRow"}, "a transition's when: is judged over the same row on both paths: the stored row, old_<column> and the actor's session keys"},
	"rowWithOldValues":               {nil, "plumbing: adds old_<column> to a transition's event row; a command's update rows carry the same before-image"},
	"injectSessionContext":           {[]string{"injectSessionContext"}, "hook, validator and effect rows carry the trusted actor context"},
	"markSubmittedFields":            {[]string{"markSubmittedFields"}, "{{_submitted}} for before-hooks and validators"},
	"encryptedDefFor":                {[]string{"commandVerifiedTriggerFunction", "maskEncryptedFieldsWith"}, "encryption triggers run inside the command statement; reads use the shared per-row unmask policy through the command transaction"},
	"sanitizeResponseRows":           {[]string{"appMCPProjectCommandResult", "validateAppMCPSchemaValue"}, "readback leaves only through the reviewed projection and closed output schema"},
	"LogAuditTx":                     {[]string{"appMCPAudit"}, "prepare, approve and commit are audited with the prepared digest; the business change is sealed in the receipt"},
	"createIdempotencyIdentity":      {[]string{"appMCPClaimAttempt"}, "the operation id and its durable attempt make _commit idempotent"},
	"batchCreateIdempotencyIdentity": {[]string{"appMCPClaimAttempt"}, "the operation id and its durable attempt make _commit idempotent"},
	"answerIdempotentReplay":         {[]string{"appMCPClaimAttempt"}, "the operation id and its durable attempt make _commit idempotent"},
	"sealIdempotentResponse":         {[]string{"appMCPClaimAttempt"}, "the operation id and its durable, sealed attempt make _commit idempotent; a command stores no response in _benmore_idempotency"},
	"CheckLock":                      {[]string{"appMCPCommandRowLocked"}, "a probed row another user holds a live edit lock on is refused as conflict"},
	"canonicalRecordLocked":          {[]string{"appMCPCommandRowLocked"}, "restore checks the same edit lock inside its transaction after authorizing the deleted row"},
	"batchLockedBy":                  {[]string{"appMCPCommandRowLocked"}, "a probed row another user holds a live edit lock on is refused as conflict"},
	"foreignKeyTargetDenial":         {[]string{"appMCPCompareCommandDependencies"}, commandParityAuthored},
	"restoreForeignKeyTargetDenial":  {[]string{"appMCPCompareCommandDependencies"}, commandParityAuthored},
	"lockErrorResponse":              {[]string{"appMCPCommandRowLocked"}, "a probed row another user holds a live edit lock on is refused as conflict"},
	"ExtractValidationRules":         {[]string{"validateAppMCPSchemaValue"}, "page :validate attributes are browser-form rules; command values are checked against closed reviewed schemas"},
	"ExtractValidationRulesWith":     {[]string{"validateAppMCPSchemaValue"}, "page :validate attributes are browser-form rules; command values are checked against closed reviewed schemas"},
	"ValidateFields":                 {[]string{"validateAppMCPSchemaValue"}, "page :validate attributes are browser-form rules; command values are checked against closed reviewed schemas"},
	"memberOfAutoJoinWith":           {[]string{"appMCPCompareCommandDependencies"}, commandParityAuthored},
	"memberOfCreateDenial":           {[]string{"appMCPCompareCommandDependencies"}, commandParityAuthored},
	"memberOfCreateDenialWith":       {[]string{"appMCPCompareCommandDependencies"}, commandParityAuthored},
	"memberOfFor":                    {[]string{"appMCPCompareCommandDependencies"}, commandParityAuthored},
	"memberOfAutoJoins":              {[]string{"appMCPCompareCommandDependencies"}, commandParityAuthored},
	"memberOfRepointDenialWith":      {[]string{"appMCPCompareCommandDependencies"}, commandParityAuthored},
	"rowScopeClause":                 {[]string{"appMCPCompareCommandDependencies"}, commandParityAuthored},
	"canAccessRowScoped":             {[]string{"appMCPCompareCommandDependencies"}, commandParityAuthored},
	"txAuthorizedRow":                {[]string{"appMCPCompareCommandDependencies"}, commandParityAuthored},
	"txAuthorizedRowMode":            {[]string{"appMCPCompareCommandDependencies"}, commandParityAuthored},
	"prepareUpdateTimestamp":         {[]string{"appMCPCompareCommandDependencies"}, "generic CRUD compares the client timestamp and advances its version; approved commands re-check the exact prepared row dependencies before executing their reviewed SQL"},

	// Exempt.
	"membershipCreateIdentityDenial": {nil, "author-scoped: refuses a request value generic CRUD would replace with the caller's id; reviewed command SQL binds the member it names, so nothing is replaced and it can add another user"},

	"protectedUpdateFields":        {nil, "author-scoped: the reviewed apply SQL names every column it writes; framework tables are never writable by command SQL"},
	"protectedCreateFields":        {nil, "author-scoped: the reviewed apply SQL names every column it writes; framework tables are never writable by command SQL"},
	"sealNativeCiphertextLiterals": {nil, "canonical native connector updates share plaintext sealing through txUpdateMode; approved commands author trusted storage SQL, so their encryption triggers retain ciphertext idempotence just like authored flow SQL and key rotation"},
	"uploadsAllowed":               {[]string{"appMCPAddTransferPreview"}, "features.uploads: false; commands cannot upload, and the one way a command stores a file, an approved pull, is refused by the same check at prepare (and again at delivery and at the store step)"},
	"uploadFilePart":               {nil, "names the file part of an HTTP multipart create for the uploads_disabled refusal; commands take no multipart body"},
	"writeUploadsDisabled":         {nil, "the HTTP refusal of a multipart create's file part while uploads are off; a command's pull answers the connector's denied result instead"},
	"acquireUploadSlot":            {nil, "commands cannot upload; approved file pulls are transfer effects"},
	"removeMultipartTemp":          {nil, "commands cannot upload; approved file pulls are transfer effects"},
	"uploadClientKey":              {nil, "commands cannot upload; approved file pulls are transfer effects"},
	"requiresUserIDInsert":         {nil, "author-scoped: the reviewed apply SQL supplies its own owner column"},
	"ownerOrTenantReplaced":        {nil, "author-scoped: reports a request's replaced owner or tenant in X-Stripped-Fields; reviewed command SQL binds its own owner and tenant columns, so no request value is ever replaced"},
	"cascadeSoftDelete":            {nil, "author-scoped: the reviewed apply SQL names every row it deletes"},
	"cascadeSoftDeleteChildren":    {nil, "author-scoped: the reviewed apply SQL names every row it deletes"},
	"execVersioned":                {[]string{"appMCPCommandAttributeVersions"}, "the verified history triggers record the versions inside the command statement; the versions an apply recorded are stamped with the approving actor in the command transaction"},
	"SessionCanAccessTable":        {nil, "author-scoped: the reviewed apply SQL names every row it deletes; a CRUD cascade checks the child table's delete mode for the deleting caller"},
	"ownedFieldChecker":            {nil, commandParityOwned},
	"ownedFieldViolation":          {nil, commandParityOwned},
	"ownedUpdateDrop":              {nil, commandParityOwned},
	"respondOwnedField":            {nil, commandParityOwned},
	"dropMaskedEchoes":             {nil, "generic CRUD round-trip: an edit form sends back the encrypted-field mask its caller read; command inputs come from a reviewed closed schema, not an echoed masked row, and command SQL names every column it writes"},
	"maskedEchoFields":             {nil, "generic CRUD round-trip: an edit form sends back the encrypted-field mask its caller read; command inputs come from a reviewed closed schema, not an echoed masked row, and command SQL names every column it writes"},
	"writeOwnedFieldRefusal":       {nil, commandParityOwned},
	"checkStorageCap":              {nil, "the storage ceiling is enforced by the sqlite3_benmore driver on the command's own connection; this projects multipart upload size and commands cannot upload"},
	"respondStorageFull":           {nil, "the storage ceiling is enforced by the sqlite3_benmore driver on the command's own connection"},
	"isStorageFullError":           {nil, "the storage ceiling is enforced by the sqlite3_benmore driver on the command's own connection"},
	"writeUploadRefusal":           {nil, "HTTP status mapping only for a multipart create whose file was refused (413 size, 415 type, 507 + used and limit bytes for the account's media storage allowance); the allowance itself is enforced where the storage backend asks the router for an upload URL, so the one way a command stores a file, an approved pull (appMCPStorePulledFile, the same backend Save), meets the same refusal and its transfer job fails without storing"},
	"respondDatabaseBusy":          {nil, "HTTP status mapping only (503 + Retry-After); a command attempt that hits a lock timeout fails retryable through the operation lifecycle"},
	"answerIfRequestBodyTooLarge":  {nil, "HTTP status mapping only (413 + the limit) for a request body over its cap; command inputs arrive in the connector call and are bounded by the closed input schema"},
	"writeBatchTooLarge":           {nil, "HTTP status mapping only (413 + the limit) for a batch or transaction naming more than maxBatchItems rows; a command's writes are its own reviewed SQL, bounded by the command's own limits"},
	"writeTableRefusal":            {nil, "HTTP status mapping only: a refusal answers the unmatched-route 404 to a caller who may not read the table (security.md 14f); commands name their tables in the reviewed manifest"},
	"writeUnmatchedAPINotFound":    {nil, "HTTP status mapping only (the unmatched-route 404); commands name their tables in the reviewed manifest"},
	"extendBulkBodyDeadlines":      {nil, "HTTP connection deadlines for a streaming request body; command inputs arrive in the connector call and are bounded by the closed input schema"},
	"parseFormBody":                {nil, "HTTP form decoding only (an urlencoded body cut by the body cap is reported, not read as no fields); command inputs arrive in the connector call, not as a form"},
	"handleFileUploadAt":           {nil, "commands cannot upload; approved file pulls are transfer effects"},
	"discardStoredUpload":          {nil, "removes files a refused HTTP multipart create stored; commands cannot upload, so they store none"},
	"createTakesFileField":         {nil, "decides which file parts of an HTTP multipart create are stored; commands take no multipart body"},
	"columnNamed":                  {nil, "names an unstored file part of an HTTP multipart create in X-Stripped-Fields; commands take no multipart body"},
	"multipartRequest":             {nil, "picks the hint of an HTTP update that read no field from a multipart body; commands take no multipart body"},
	"validateCSRF":                 {nil, "approval is a session-bound CSRF-checked POST; _commit is an authenticated connector call, not a cookie request"},
	"isBearerAuth":                 {nil, "approval is a session-bound CSRF-checked POST; _commit is an authenticated connector call, not a cookie request"},
	"Increment":                    {nil, "usage metering only, no enforcement; connector outcomes are counted by MCP telemetry"},
	"meterScope":                   {nil, "usage metering only, no enforcement; connector outcomes are counted by MCP telemetry"},
	"appLimiterKey":                {nil, "HTTP rate limiting; connector operations have their own per-actor and per-IP limits"},
	"setRetryAfter":                {nil, "HTTP rate limiting (the ingest 429's Retry-After header); connector operations have their own per-actor and per-IP limits"},

	"membershipActivationDenial":  {nil, "author-scoped: the reviewed apply SQL names every column it writes and binds its own tenant to user.group_id"},
	"membershipCreateDenial":      {nil, commandParityMembership},
	"membershipUpdateDenial":      {nil, commandParityMembership},
	"membershipDeleteDenial":      {nil, commandParityMembership},
	"writeMembershipManageDenial": {nil, commandParityMembership},

	"applyCanonicalUpdateTx":            {nil, commandParityPipeline},
	"handleCreate":                      {nil, commandParityPipeline},
	"handleUpdate":                      {nil, commandParityPipeline},
	"txInsert":                          {nil, commandParityPipeline},
	"txUpdateMode":                      {nil, commandParityPipeline},
	"applyCanonicalUpdateTxContextMode": {nil, commandParityPipeline},
	"requireAPIAuthForOp":               {nil, commandParityPipeline},
	"txDelete":                          {nil, commandParityPipeline},
	"txDeleteRow":                       {nil, commandParityPipeline},
	"txInsertWithPlan":                  {nil, commandParityPipeline},
	"newInsertPlan":                     {nil, commandParityPipeline},
	"validateTxMutation":                {nil, commandParityPipeline},
	"validateTxMutationRules":           {nil, commandParityPipeline},

	// queryNativeRowsWith's parts: NDJSON ingest reads each row back for its
	// audit entry with the database key resolved once per request.
	"cryptoKeyForQuerier":            {nil, "same decision as queryNativeRowsWith, whose key lookup it is"},
	"nativeRowDecryptor":             {nil, "same decision as queryNativeRowsWith, whose decoder it is"},
	"queryRowsWithKeyContextDecrypt": {nil, "same decision as queryNativeRowsWith, whose query it is"},

	"normalizeUserDeactivationValue": {nil, "stores an emptied deactivated_at of a _benmore_users row as NULL (only NULL reads as active); command SQL cannot write framework tables, so no command writes that column"},

	"FormatValidationErrors":    {nil, commandParityPlumbing},
	"copyRow":                   {nil, commandParityPlumbing},
	"safeIdent":                 {nil, commandParityPlumbing},
	"lastDurableAdminUpdate":    {nil, "the last-admin guard protects _benmore_users rows (deactivation, role, verification); command SQL cannot write framework tables, so no command can remove the last admin"},
	"refuseLastAdminRowDelete":  {nil, "the last-admin guard on deleting a _benmore_users row; command SQL cannot write framework tables, so no command can delete an account"},
	"userIdentifierUpdate":      {nil, "the identifier guard on _benmore_users rows (another admin's sign-in address is refused, any other address change revokes the account's credentials); command SQL cannot write framework tables, so no command can change an account's identifier"},
	"purgeRowKeyedState":        {nil, "framework bookkeeping after a generic CRUD hard delete (stale record shares and locks); command SQL cannot write framework tables, so a command's own hard delete leaves them, which matters only for keys without AUTOINCREMENT"},
	"rowIDCanonical":            {nil, "author-scoped: a command addresses rows through its own reviewed SQL and typed inputs, not a request path id; framework lock/share state is never keyed by a command"},
	"GetTableColumns":           {nil, commandParityPlumbing},
	"appTableColumns":           {nil, commandParityPlumbing},
	"GetTableNames":             {nil, commandParityPlumbing},
	"queryNativeRowsWith":       {nil, "native canonical mutations decode only configured physical columns using their known source table; reviewed authored command SQL retains the separate generic SQL decoding compatibility contract"},
	"accessOpForMethod":         {nil, commandParityPlumbing},
	"appendHXTrigger":           {nil, commandParityPlumbing},
	"extractID":                 {nil, commandParityPlumbing},
	"identIs":                   {nil, commandParityPlumbing},
	"valueText":                 {nil, commandParityPlumbing},
	"setIgnoredFieldsHeader":    {nil, commandParityPlumbing},
	"addIgnoredFields":          {nil, commandParityPlumbing},
	"updateStrippedFields":      {nil, commandParityPlumbing},
	"strippedUpdateHint":        {nil, commandParityPlumbing},
	"mutationErrorResponse":     {nil, commandParityPlumbing},
	"publicConstraintMessage":   {nil, commandParityPlumbing},
	"writeFKTargetDenial":       {nil, commandParityPlumbing},
	"getSession":                {nil, commandParityPlumbing},
	"getUpdateFields":           {nil, commandParityPlumbing},
	"hasColumn":                 {nil, commandParityPlumbing},
	"hasColumnInList":           {nil, "response shaping only: the create response adds the legacy status marker only when the table has no status column; this schema lookup performs no authorization or mutation"},
	"httpError":                 {nil, commandParityPlumbing},
	"httpRefusal":               {nil, commandParityPlumbing},
	"scopeDeniedBody":           {nil, commandParityPlumbing},
	"withRefusalDocs":           {nil, commandParityPlumbing},
	"httpJSON":                  {nil, commandParityPlumbing},
	"withWriteTxLabel":          {nil, "names the write transaction in write-lock logs; no authorization or mutation"},
	"isHTMX":                    {nil, commandParityPlumbing},
	"canonicalJSONNumberID":     {nil, commandParityPlumbing},
	"jsonToUpdateValue":         {nil, commandParityPlumbing},
	"prismaWriteColumns":        {nil, "generic CRUD captures the loaded Prisma scalar metadata; command inputs use the reviewed closed input schema"},
	"prepareJSONCreateData":     {nil, commandParityPlumbing},
	"normalizePrismaValue":      {[]string{"validateAppMCPSchemaValue"}, "generic CRUD validates raw values against loaded Prisma declarations; commands validate closed reviewed input schemas before their authored SQL"},
	"normalizePrismaFields":     {[]string{"validateAppMCPSchemaValue"}, "generic CRUD validates raw values against loaded Prisma declarations; commands validate closed reviewed input schemas before their authored SQL"},
	"requirePrismaCreateFields": {[]string{"validateAppMCPSchemaValue"}, "generic CRUD requires declared non-null fields without defaults; commands require fields from their reviewed input schema and author their SQL defaults"},
	"jsonToFormValue":           {nil, commandParityPlumbing},
	"loadInsertedRowWith":       {nil, commandParityPlumbing},
	"mainTableColumnsWith":      {nil, commandParityPlumbing},
	"mapKeys":                   {nil, commandParityPlumbing},
	"quoteIdent":                {nil, commandParityPlumbing},
	"quoteColumn":               {nil, commandParityPlumbing},
	"quoteIdents":               {nil, commandParityPlumbing},
	"tableColumnsWith":          {nil, commandParityPlumbing},
	"tableHasUniqueUserID":      {nil, commandParityPlumbing},
	"updateInternalError":       {nil, commandParityPlumbing},
	"unauthenticatedAPIBody":    {nil, commandParityPlumbing},
	"writeMemberOfDenial":       {nil, commandParityPlumbing},
	// Server-error answers (server_error.go): the HTTP shape of a failure
	// and its request-log/journal record. A command failure is recorded by
	// the operation lifecycle (appMCPLogCommandError, attempt rows) instead.
	"serverError":             {nil, commandParityPlumbing},
	"serverErrorJSON":         {nil, commandParityPlumbing},
	"serverErrorJSONBody":     {nil, commandParityPlumbing},
	"writeUpdateRequestError": {nil, commandParityPlumbing},
	// Names the column behind a FOREIGN KEY failure the database already
	// raised: it shapes that refusal and refuses nothing itself.
	"foreignKeyConstraintDenial": {nil, commandParityPlumbing},
}

// packageCalls parses the package's non-test sources and returns, for the named
// functions, the package-level functions each calls, plus every package-level
// function called anywhere in the given files.
func packageCalls(t *testing.T, functions, files []string) (map[string]map[string]bool, map[string]bool) {
	t.Helper()
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	wantFunc := map[string]bool{}
	for _, name := range functions {
		wantFunc[name] = true
	}
	wantFile := map[string]bool{}
	for _, name := range files {
		wantFile[name] = true
	}
	fset := token.NewFileSet()
	defined := map[string]bool{}
	var parsed []*ast.File
	var names []string
	for _, source := range sources {
		if strings.HasSuffix(source, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, source, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", source, err)
		}
		parsed = append(parsed, file)
		names = append(names, source)
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil {
				defined[fn.Name.Name] = true
			}
		}
	}
	calledBy := map[string]map[string]bool{}
	inFiles := map[string]bool{}
	collect := func(node ast.Node, into map[string]bool) {
		ast.Inspect(node, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if ident, ok := call.Fun.(*ast.Ident); ok && defined[ident.Name] {
					into[ident.Name] = true
				}
			}
			return true
		})
	}
	for i, file := range parsed {
		if wantFile[names[i]] {
			collect(file, inFiles)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !wantFunc[fn.Name.Name] || fn.Body == nil {
				continue
			}
			if calledBy[fn.Name.Name] == nil {
				calledBy[fn.Name.Name] = map[string]bool{}
			}
			collect(fn.Body, calledBy[fn.Name.Name])
		}
	}
	for _, name := range files {
		found := false
		for _, source := range names {
			found = found || source == name
		}
		if !found {
			t.Fatalf("command write path file %s no longer exists; update commandWritePathFiles", name)
		}
	}
	return calledBy, inFiles
}

func TestAppMCPCommandCRUDGuardParityInventory(t *testing.T) {
	// Commands use the transaction-aware entry point; HTTP responses use its
	// App wrapper. Assert both still reach the same per-row policy, so a
	// helper rename cannot silently weaken the encryption parity inventory.
	maskingPath := []string{"sanitizeResponseRows", "MaskEncryptedFields", "maskEncryptedFieldsWith", "encryptedFieldAccessFor"}
	functions := append(append([]string(nil), crudWritePipeline...), maskingPath...)
	calledBy, commandCalls := packageCalls(t, functions, commandWritePathFiles)
	for i := 0; i+1 < len(maskingPath); i++ {
		if !calledBy[maskingPath[i]][maskingPath[i+1]] {
			t.Errorf("shared encryption policy path %s no longer calls %s", maskingPath[i], maskingPath[i+1])
		}
	}
	used := map[string][]string{}
	for _, name := range crudWritePipeline {
		calls, ok := calledBy[name]
		if !ok {
			t.Errorf("CRUD write pipeline function %s no longer exists; update crudWritePipeline", name)
			continue
		}
		for call := range calls {
			used[call] = append(used[call], name)
		}
	}
	var unclassified []string
	for call, callers := range used {
		if _, ok := crudGuardCommandParity[call]; !ok {
			sort.Strings(callers)
			unclassified = append(unclassified, call+" (called by "+strings.Join(callers, ", ")+")")
		}
	}
	sort.Strings(unclassified)
	for _, call := range unclassified {
		t.Errorf("CRUD write pipeline calls %s, which has no approved-command parity decision in crudGuardCommandParity", call)
	}
	for name, rule := range crudGuardCommandParity {
		if len(used[name]) == 0 {
			t.Errorf("stale parity entry %s: the CRUD write pipeline no longer calls it", name)
		}
		if rule.why == "" {
			t.Errorf("parity entry %s has no reason", name)
		}
		for _, counterpart := range rule.counterparts {
			if !commandCalls[counterpart] {
				t.Errorf("CRUD guard %s relies on %s on the approved-command path, which no longer calls it", name, counterpart)
			}
		}
	}
}
