import { ApiError, apiDownload, apiEventStream, apiRequest, type PaginatedDTO } from "@/shared/api/client";
import { createObjectDecoder, createPaginatedDecoder, createValidatedDecoder, decodeBooleanResult, decodeCountResult, hasShape, isArrayOf, isBoolean, isNumber, isOneOf, isOptional, isRecordOf, isString } from "@/shared/api/decoder";
import { i18n } from "@/shared/i18n";
import type { SortOrder } from "@/shared/lib/table-sort";

export type AccountProvider = "grok_build" | "grok_web" | "grok_console";
export type BuildRouteMode = "auto" | "build" | "xai";
export type AccountCleanupStatus = "cooldown" | "disabled" | "reauthRequired";

export type BillingDTO = {
  planCode?: string;
  planName?: string;
  monthlyLimit: number;
  used: number;
  remaining: number;
  onDemandCap: number;
  onDemandUsed: number;
  prepaidBalance: number;
  creditUsagePercent: number;
  isUnifiedBillingUser: boolean;
  onDemandEnabled?: boolean;
  topUpMethod?: string;
  usagePeriodType?: string;
  usagePeriodStart?: string;
  usagePeriodEnd?: string;
  billingPeriodStart?: string;
  billingPeriodEnd?: string;
  history?: BillingHistoryDTO[];
  syncedAt: string;
};

export type BillingHistoryDTO = {
  year: number;
  month: number;
  periodType?: string;
  periodStart?: string;
  periodEnd?: string;
  includedUsed: number;
  onDemandUsed: number;
  totalUsed: number;
};

export type QuotaDTO = {
  type: "free" | "paid" | "unknown";
  source: "unknown" | "upstreamBilling" | "upstreamExhaustion" | "responseModel" | "billingProfile" | "buildSuperEntitlement";
  confidence: "estimated" | "observed" | "confirmed" | "";
  status: "active" | "waitingReset" | "probing";
  unit?: "tokens" | "credits" | "percent";
  used: number;
  limit: number;
  remaining: number;
  usagePercent: number;
  limitKnown: boolean;
  windowHours?: number;
  observed: boolean;
  confirmed: boolean;
  periodStart?: string;
  periodEnd?: string;
  exhaustedAt?: string;
  nextProbeAt?: string;
  lastConfirmedAt?: string;
};

export type AccountDTO = {
  id: string;
  provider: AccountProvider;
  authType: "oauth" | "sso";
  webTier?: "auto" | "basic" | "super" | "heavy";
  webTierSyncedAt?: string;
  nsfwEnabledAt?: string;
  termsAcceptedAt?: string;
  name: string;
  email?: string;
  userId?: string;
  teamId?: string;
  enabled: boolean;
  authStatus: "active" | "reauthRequired";
  reauthReason?: string;
  reauthReasonLabel?: string;
  expiresAt?: string;
  refreshable: boolean;
  cloudflareCookieConfigured: boolean;
  buildSuperEntitled: boolean;
  buildRouteMode: BuildRouteMode;
  buildBotFlagged: boolean;
  modelSyncFailed?: boolean;
  refreshDueAt?: string;
  lastRefreshAt?: string;
  refreshFailureCount: number;
  lastRefreshErrorCode?: string;
  priority: number;
  maxConcurrent: number;
  minimumRemaining: number;
  failureCount: number;
  cooldownUntil?: string;
  lastError?: string;
  lastUsedAt?: string;
  linkedAccountId?: string;
  linkedAccountName?: string;
  linkedProvider?: "grok_build" | "grok_web";
  linkedAccounts?: LinkedAccountDTO[];
  createdAt: string;
  billing?: BillingDTO;
  quota: QuotaDTO;
  quotaWindows?: Array<{ mode: string; remaining: number; total: number; usagePercent: number; breakdown?: Array<{ productCode: number; usagePercent: number }>; windowSeconds: number; resetAt?: string; syncedAt?: string; source: "default" | "estimated" | "upstream" }>;
  /** Build CLI layering diagnostics (optional; absent for Web/Console). */
  cliLayer?: number;
  cliEligibility?: string;
  cliWarmBucket?: string;
  cliLastSuccessAt?: string;
  cliTrustedSource?: boolean;
  cliMaybeDead?: boolean;
  cliCallCount?: number;
  cliTokenGeneration?: number;
};

export type AccountImportOptions = {
  autoSyncConsole?: boolean;
  trustedSource?: boolean;
};

export type CLIPoolSnapshotDTO = {
  readyTotal: number;
  unprovenReady: number;
  unprovenCap: number;
  target: number;
  readyByBucket: Record<string, number>;
  updatedAt: string;
};

export type LinkedAccountDTO = {
  id: string;
  provider: "grok_build" | "grok_web" | "grok_console";
  name: string;
  email?: string;
  userId?: string;
};

export type AccountUpdateInput = {
  name: string;
  enabled: boolean;
  priority: number;
  maxConcurrent: number;
  minimumRemaining: number;
  cloudflareCookies?: string;
  clearCloudflareCookies?: boolean;
  buildSuperEntitled?: boolean;
  buildRouteMode?: BuildRouteMode;
};

export type AccountSummaryDTO = {
  total: number;
  available: number;
  recovering: number;
  attention: number;
  risk: number;
  providers: Record<AccountProvider, { total: number; available: number }>;
  recovery: { cooldown: number; waitingReset: number; probing: number };
  issues: { disabled: number; reauthRequired: number };
};

export type DeviceSessionDTO = {
  sessionId: string;
  userCode: string;
  verificationUri: string;
  verificationUriComplete?: string;
  intervalSeconds: number;
  expiresAt: string;
};

export type DevicePollDTO = {
  status: "pending" | "succeeded" | "syncFailed";
  account?: AccountDTO;
  synced?: number;
  syncFailed?: number;
};

const billingHistoryValidator = hasShape({
  year: isNumber, month: isNumber, periodType: isOptional(isString), periodStart: isOptional(isString), periodEnd: isOptional(isString),
  includedUsed: isNumber, onDemandUsed: isNumber, totalUsed: isNumber,
});
const billingValidator = hasShape({
  planCode: isOptional(isString), planName: isOptional(isString), monthlyLimit: isNumber, used: isNumber, remaining: isNumber,
  onDemandCap: isNumber, onDemandUsed: isNumber, prepaidBalance: isNumber, creditUsagePercent: isNumber,
  isUnifiedBillingUser: isBoolean, onDemandEnabled: isOptional(isBoolean), topUpMethod: isOptional(isString), usagePeriodType: isOptional(isString),
  usagePeriodStart: isOptional(isString), usagePeriodEnd: isOptional(isString), billingPeriodStart: isOptional(isString),
  billingPeriodEnd: isOptional(isString), history: isOptional(isArrayOf(billingHistoryValidator)), syncedAt: isString,
});
const quotaValidator = hasShape({
  type: isOneOf("free", "paid", "unknown"), source: isOneOf("unknown", "upstreamBilling", "upstreamExhaustion", "responseModel", "billingProfile", "buildSuperEntitlement"),
  confidence: isOneOf("estimated", "observed", "confirmed", ""), status: isOneOf("active", "waitingReset", "probing"),
  unit: isOptional(isOneOf("tokens", "credits", "percent")), used: isNumber, limit: isNumber, remaining: isNumber, usagePercent: isNumber,
  limitKnown: isBoolean, windowHours: isOptional(isNumber), observed: isBoolean, confirmed: isBoolean,
  periodStart: isOptional(isString), periodEnd: isOptional(isString), exhaustedAt: isOptional(isString),
  nextProbeAt: isOptional(isString), lastConfirmedAt: isOptional(isString),
});
const quotaBreakdownValidator = hasShape({ productCode: isNumber, usagePercent: isNumber });
const quotaWindowValidator = hasShape({
  mode: isString, remaining: isNumber, total: isNumber, usagePercent: isNumber, breakdown: isOptional(isArrayOf(quotaBreakdownValidator)),
  windowSeconds: isNumber, resetAt: isOptional(isString), syncedAt: isOptional(isString), source: isOneOf("default", "estimated", "upstream"),
});
const linkedAccountValidator = hasShape({ id: isString, provider: isOneOf("grok_build", "grok_web", "grok_console"), name: isString, email: isOptional(isString), userId: isOptional(isString) });
const accountValidator = hasShape({
  id: isString, provider: isOneOf("grok_build", "grok_web", "grok_console"), authType: isOneOf("oauth", "sso"), webTier: isOptional(isOneOf("auto", "basic", "super", "heavy")),
  webTierSyncedAt: isOptional(isString), nsfwEnabledAt: isOptional(isString), termsAcceptedAt: isOptional(isString), name: isString, email: isOptional(isString), userId: isOptional(isString), teamId: isOptional(isString),
  enabled: isBoolean, authStatus: isOneOf("active", "reauthRequired"), reauthReason: isOptional(isString), reauthReasonLabel: isOptional(isString), expiresAt: isOptional(isString), refreshable: isBoolean, cloudflareCookieConfigured: isBoolean,
  buildSuperEntitled: isBoolean, buildRouteMode: isOneOf("auto", "build", "xai"), buildBotFlagged: isBoolean, modelSyncFailed: isOptional(isBoolean), refreshDueAt: isOptional(isString), lastRefreshAt: isOptional(isString), refreshFailureCount: isNumber,
  lastRefreshErrorCode: isOptional(isString), priority: isNumber, maxConcurrent: isNumber, minimumRemaining: isNumber,
  failureCount: isNumber, cooldownUntil: isOptional(isString), lastError: isOptional(isString), lastUsedAt: isOptional(isString),
  linkedAccountId: isOptional(isString), linkedAccountName: isOptional(isString), linkedProvider: isOptional(isOneOf("grok_build", "grok_web")), linkedAccounts: isOptional(isArrayOf(linkedAccountValidator)),
  createdAt: isString, billing: isOptional(billingValidator), quota: quotaValidator, quotaWindows: isOptional(isArrayOf(quotaWindowValidator)),
  cliLayer: isOptional(isNumber), cliEligibility: isOptional(isString), cliWarmBucket: isOptional(isString),
  cliLastSuccessAt: isOptional(isString), cliTrustedSource: isOptional(isBoolean), cliMaybeDead: isOptional(isBoolean),
  cliCallCount: isOptional(isNumber), cliTokenGeneration: isOptional(isNumber),
});
const decodeBilling = createValidatedDecoder<BillingDTO>("billing", billingValidator);
const decodeAccount = createValidatedDecoder<AccountDTO>("account", accountValidator);
const decodeAccountPage = createPaginatedDecoder<AccountDTO>(accountValidator);
const decodeAccountSummary = createObjectDecoder<AccountSummaryDTO>("account summary", {
  total: isNumber, available: isNumber, recovering: isNumber, attention: isNumber, risk: isNumber,
  providers: isRecordOf(hasShape({ total: isNumber, available: isNumber })),
  recovery: hasShape({ cooldown: isNumber, waitingReset: isNumber, probing: isNumber }),
  issues: hasShape({ disabled: isNumber, reauthRequired: isNumber }),
});
const decodeDeviceSession = createObjectDecoder<DeviceSessionDTO>("device session", {
  sessionId: isString, userCode: isString, verificationUri: isString, verificationUriComplete: isOptional(isString),
  intervalSeconds: isNumber, expiresAt: isString,
});
const decodeDevicePoll = createObjectDecoder<DevicePollDTO>("device poll", {
  status: isOneOf("pending", "succeeded", "syncFailed"), account: isOptional(accountValidator), synced: isOptional(isNumber), syncFailed: isOptional(isNumber),
});

type ListAccountsInput = {
  page: number;
  pageSize: number;
  search?: string;
  type?: string;
  status?: string;
  renewal?: string;
  risk?: string;
  cliLayer?: string;
  cliTrusted?: string;
  cliMaybeDead?: string;
  provider: AccountProvider;
  sortBy?: string;
  sortOrder?: SortOrder;
};

export function listAccounts(input: ListAccountsInput): Promise<PaginatedDTO<AccountDTO>> {
  const query = new URLSearchParams({ page: String(input.page), pageSize: String(input.pageSize) });
  if (input.search) query.set("search", input.search);
  if (input.type) query.set("type", input.type);
  if (input.status) query.set("status", input.status);
  if (input.renewal) query.set("renewal", input.renewal);
  if (input.risk) query.set("risk", input.risk);
  if (input.cliLayer) query.set("cliLayer", input.cliLayer);
  if (input.cliTrusted) query.set("cliTrusted", input.cliTrusted);
  if (input.cliMaybeDead) query.set("cliMaybeDead", input.cliMaybeDead);
  if (input.sortBy && input.sortOrder) {
    query.set("sortBy", input.sortBy);
    query.set("sortOrder", input.sortOrder);
  }
  query.set("provider", input.provider);
  return apiRequest(`/api/admin/v1/accounts?${query}`, {}, decodeAccountPage);
}

export type AccountSnapshotDTO = {
  items: AccountDTO[];
  total: number;
  revision: number;
  provider: AccountProvider;
  generatedAt: string;
};

export type AccountChangesDTO = {
  revision: number;
  fullResync: boolean;
};

export type AccountSnapshotInput = Omit<ListAccountsInput, "page" | "pageSize">;

const decodeAccountSnapshot = createValidatedDecoder<AccountSnapshotDTO>("accountSnapshot", hasShape({
  items: isArrayOf(accountValidator),
  total: isNumber,
  revision: isNumber,
  provider: isOneOf("grok_build", "grok_web", "grok_console"),
  generatedAt: isString,
}));

const decodeAccountChanges = createValidatedDecoder<AccountChangesDTO>("accountChanges", hasShape({
  revision: isNumber,
  fullResync: isBoolean,
}));

/** Provider-scoped full list for client-side paging (page flips do not re-hit the API). */
export function fetchAccountSnapshot(input: AccountSnapshotInput): Promise<AccountSnapshotDTO> {
  const query = new URLSearchParams({ provider: input.provider });
  if (input.search) query.set("search", input.search);
  if (input.type) query.set("type", input.type);
  if (input.status) query.set("status", input.status);
  if (input.renewal) query.set("renewal", input.renewal);
  if (input.risk) query.set("risk", input.risk);
  if (input.cliLayer) query.set("cliLayer", input.cliLayer);
  if (input.cliTrusted) query.set("cliTrusted", input.cliTrusted);
  if (input.cliMaybeDead) query.set("cliMaybeDead", input.cliMaybeDead);
  if (input.sortBy && input.sortOrder) {
    query.set("sortBy", input.sortBy);
    query.set("sortOrder", input.sortOrder);
  }
  return apiRequest(`/api/admin/v1/accounts/snapshot?${query}`, {}, decodeAccountSnapshot);
}

export function fetchAccountChanges(since: number): Promise<AccountChangesDTO> {
  const query = new URLSearchParams({ since: String(since) });
  return apiRequest(`/api/admin/v1/accounts/changes?${query}`, {}, decodeAccountChanges);
}

export function getAccountSummary(): Promise<AccountSummaryDTO> {
  return apiRequest("/api/admin/v1/accounts/summary", {}, decodeAccountSummary);
}

export function updateAccount(id: string, input: AccountUpdateInput): Promise<AccountDTO> {
  return apiRequest(`/api/admin/v1/accounts/${id}`, { method: "PATCH", body: input }, decodeAccount);
}

export function deleteAccount(id: string): Promise<{ deleted: boolean }> {
  return apiRequest(`/api/admin/v1/accounts/${id}`, { method: "DELETE" }, decodeBooleanResult<{ deleted: boolean }>("deleted"));
}

export function refreshAccountBilling(id: string): Promise<BillingDTO> {
  return apiRequest(`/api/admin/v1/accounts/${id}/refresh-billing`, { method: "POST" }, decodeBilling);
}

export function refreshAccountToken(id: string): Promise<AccountDTO> {
  return apiRequest(`/api/admin/v1/accounts/${id}/refresh-token`, { method: "POST" }, decodeAccount);
}

export function acceptWebAccountTerms(id: string): Promise<{ completed: boolean }> {
  return apiRequest(`/api/admin/v1/accounts/web/${id}/accept-terms`, { method: "POST" }, decodeBooleanResult<{ completed: boolean }>("completed"));
}

export function setWebAccountBirthDate(id: string): Promise<{ completed: boolean }> {
  return apiRequest(`/api/admin/v1/accounts/web/${id}/birth-date`, { method: "POST" }, decodeBooleanResult<{ completed: boolean }>("completed"));
}

export function enableWebAccountNSFW(id: string): Promise<{ completed: boolean }> {
  return apiRequest(`/api/admin/v1/accounts/web/${id}/nsfw`, { method: "POST" }, decodeBooleanResult<{ completed: boolean }>("completed"));
}

export type AccountBatchResultDTO = { succeeded: number; failed: number };
export type AccountTokenRefreshResultDTO = AccountBatchResultDTO & { skipped: number };

export type BuildConversionResultDTO = {
  created: number;
  linked: number;
  skipped: number;
  failed: number;
  synced: number;
  syncFailed: number;
};

export type AccountSyncStrategy = "missing" | "all";
export type BuildConversionStrategy = AccountSyncStrategy;
export type WebConsoleSyncStrategy = AccountSyncStrategy;

// trustedSource on convert is deprecated (SSO/import property); kept optional for old clients only.
export type BuildConversionInput =
  | { all: true; ids?: never; strategy?: BuildConversionStrategy; trustedSource?: boolean; async?: boolean }
  | { all?: false; ids: string[]; strategy?: BuildConversionStrategy; trustedSource?: boolean; async?: boolean };

export type WebConsoleSyncInput =
  | { all: true; ids?: never; strategy: WebConsoleSyncStrategy; async?: boolean }
  | { all?: false; ids: string[]; strategy: WebConsoleSyncStrategy; async?: boolean };

export type WebAccountScriptActions = {
  acceptTerms: boolean;
  setBirthDate: boolean;
  enableNSFW: boolean;
};

export type WebAccountScriptScope = "pending" | "pending_nsfw" | "all_force" | "ids";

export type WebAccountScriptsInput =
  | { all: true; ids?: never; actions: WebAccountScriptActions; scope?: WebAccountScriptScope; async?: boolean }
  | { all?: false; ids: string[]; actions: WebAccountScriptActions; scope?: WebAccountScriptScope; async?: boolean };

export type AdminTaskSnapshotDTO = {
  taskId: string;
  type: string;
  label: string;
  status: "queued" | "running" | "done" | "error" | "cancelled";
  total: number;
  processed: number;
  ok: number;
  fail: number;
  error?: string;
  result?: Record<string, unknown>;
  phase?: string;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
};

export type AccountTaskProgressDTO = {
  completed: number;
  total: number;
  phase?: "importing" | "converting" | "syncing";
};

export type AccountImportResultDTO = {
  created: number;
  updated: number;
  synced: number;
  syncFailed: number;
  consoleCreated?: number;
  consoleUpdated?: number;
  consoleFailed?: number;
  consoleSkipped?: number;
};

export type WebConsoleSyncResultDTO = AccountImportResultDTO & { skipped: number };

type AccountTaskStreamPayload = Partial<BuildConversionResultDTO & AccountTaskProgressDTO & AccountTokenRefreshResultDTO & AccountImportResultDTO> & {
  code?: string;
  message?: string;
};

const decodeAccountTaskStreamPayload = createObjectDecoder<AccountTaskStreamPayload>("account task event", {
  created: isOptional(isNumber), linked: isOptional(isNumber), skipped: isOptional(isNumber), failed: isOptional(isNumber),
  synced: isOptional(isNumber), syncFailed: isOptional(isNumber), completed: isOptional(isNumber), total: isOptional(isNumber),
  phase: isOptional(isOneOf("importing", "converting", "syncing")), updated: isOptional(isNumber), succeeded: isOptional(isNumber),
  consoleCreated: isOptional(isNumber), consoleUpdated: isOptional(isNumber), consoleFailed: isOptional(isNumber), consoleSkipped: isOptional(isNumber),
  code: isOptional(isString), message: isOptional(isString),
});

function hasNumericResult(value: AccountTaskStreamPayload, fields: string[]): boolean {
  return fields.every((field) => {
    const item = value[field as keyof AccountTaskStreamPayload];
    return typeof item === "number" && Number.isInteger(item) && item >= 0;
  });
}

async function runAccountTask<T>(path: string, body: BodyInit | object | undefined, resultFields: string[], onProgress?: (value: AccountTaskProgressDTO) => void, signal?: AbortSignal): Promise<T> {
  let result: T | undefined;
  let pendingProgress: AccountTaskProgressDTO | undefined;
  let progressTimer: number | undefined;
  let lastProgressAt = 0;
  const flushProgress = () => {
    if (!pendingProgress || !onProgress) return;
    const value = pendingProgress;
    pendingProgress = undefined;
    lastProgressAt = performance.now();
    onProgress(value);
  };
  const reportProgress = (value: AccountTaskProgressDTO) => {
    if (pendingProgress && pendingProgress.phase !== value.phase && pendingProgress.completed === pendingProgress.total) {
      if (progressTimer !== undefined) window.clearTimeout(progressTimer);
      progressTimer = undefined;
      flushProgress();
    }
    pendingProgress = value;
    const delay = Math.max(0, 100 - (performance.now() - lastProgressAt));
    if (delay === 0) {
      if (progressTimer !== undefined) window.clearTimeout(progressTimer);
      progressTimer = undefined;
      flushProgress();
    } else if (progressTimer === undefined) {
      progressTimer = window.setTimeout(() => {
        progressTimer = undefined;
        flushProgress();
      }, delay);
    }
  };
  try {
    await apiEventStream(path, {
      method: "POST",
      headers: { Accept: "text/event-stream" },
      body,
      signal,
    }, decodeAccountTaskStreamPayload, ({ event, data }) => {
      if (event === "progress" && typeof data.completed === "number" && typeof data.total === "number") {
        const phase = data.phase === "importing" || data.phase === "converting" || data.phase === "syncing" ? data.phase : undefined;
        reportProgress({ completed: data.completed, total: data.total, phase });
        return;
      }
      if (event === "complete") {
        flushProgress();
        if (hasNumericResult(data, resultFields)) result = data as T;
        return;
      }
      if (event === "error") {
        const code = data.code ?? "accountConversionFailed";
        const localized = i18n.exists(`apiErrors.${code}`) ? i18n.t(`apiErrors.${code}`) : "";
        const server = typeof data.message === "string" ? data.message.trim() : "";
        const message = server && (!localized || server !== localized)
          ? (localized ? `${localized}（${server}）` : server)
          : (localized || server || i18n.t("apiErrors.requestFailed"));
        throw new ApiError(502, code, message);
      }
    });
  } finally {
    if (progressTimer !== undefined) window.clearTimeout(progressTimer);
    flushProgress();
  }
  if (!result) {
    throw new ApiError(502, "invalidResponse", i18n.t("apiErrors.invalidResponse"));
  }
  return result;
}

export function refreshAllAccountBilling(onProgress?: (value: AccountTaskProgressDTO) => void, signal?: AbortSignal): Promise<AccountBatchResultDTO> {
  return runAccountTask("/api/admin/v1/accounts/refresh-billing", undefined, ["succeeded", "failed"], onProgress, signal);
}

export function refreshAllAccountTokens(onProgress?: (value: AccountTaskProgressDTO) => void, signal?: AbortSignal): Promise<AccountTokenRefreshResultDTO> {
  return runAccountTask("/api/admin/v1/accounts/refresh-tokens", undefined, ["succeeded", "failed", "skipped"], onProgress, signal);
}

export function refreshAllWebAccountQuotas(onProgress?: (value: AccountTaskProgressDTO) => void, signal?: AbortSignal): Promise<AccountBatchResultDTO> {
  return runAccountTask("/api/admin/v1/accounts/web/refresh-quotas", undefined, ["succeeded", "failed"], onProgress, signal);
}

export function refreshAllConsoleAccountQuotas(onProgress?: (value: AccountTaskProgressDTO) => void, signal?: AbortSignal): Promise<AccountBatchResultDTO> {
  return runAccountTask("/api/admin/v1/accounts/console/refresh-quotas", undefined, ["succeeded", "failed"], onProgress, signal);
}

export function convertWebAccountsToBuild(input: BuildConversionInput, onProgress?: (value: AccountTaskProgressDTO) => void, signal?: AbortSignal): Promise<BuildConversionResultDTO> {
  const payload = { ...input, async: input.async ?? true };
  if (payload.async !== false) {
    return runJSONAdminTask("/api/admin/v1/accounts/web/convert-to-build", payload, onProgress, signal).then((result) => ({
      created: num(result.created), linked: num(result.linked), skipped: num(result.skipped), failed: num(result.failed),
      synced: num(result.synced), syncFailed: num(result.syncFailed),
    }));
  }
  return runAccountTask("/api/admin/v1/accounts/web/convert-to-build", payload, ["created", "linked", "skipped", "failed", "synced", "syncFailed"], onProgress, signal);
}

export function syncWebAccountsToConsole(input: WebConsoleSyncInput, onProgress?: (value: AccountTaskProgressDTO) => void, signal?: AbortSignal): Promise<WebConsoleSyncResultDTO> {
  const payload = { ...input, async: input.async ?? true };
  if (payload.async !== false) {
    return runJSONAdminTask("/api/admin/v1/accounts/web/sync-to-console", payload, onProgress, signal).then((result) => ({
      created: num(result.created), updated: num(result.updated), skipped: num(result.skipped),
      synced: num(result.synced), syncFailed: num(result.syncFailed),
    }));
  }
  return runAccountTask("/api/admin/v1/accounts/web/sync-to-console", payload, ["created", "updated", "skipped", "synced", "syncFailed"], onProgress, signal);
}


const decodeAdminTaskAccepted = createObjectDecoder<{ taskId: string; status?: string; scope?: string; async?: boolean }>("admin task accepted", {
  taskId: isString,
  status: isOptional(isString),
  scope: isOptional(isString),
  async: isOptional(isBoolean),
});

const decodeAdminTaskSnapshot = createObjectDecoder<AdminTaskSnapshotDTO>("admin task snapshot", {
  taskId: isString,
  type: isString,
  label: isString,
  status: isOneOf("queued", "running", "done", "error", "cancelled"),
  total: isNumber,
  processed: isNumber,
  ok: isNumber,
  fail: isNumber,
  error: isOptional(isString),
  result: isOptional(isRecordOf(() => true)),
  phase: isOptional(isString),
  createdAt: isString,
  startedAt: isOptional(isString),
  finishedAt: isOptional(isString),
});

const decodeAdminTaskList = createObjectDecoder<{ tasks: AdminTaskSnapshotDTO[] }>("admin task list", {
  tasks: isArrayOf(hasShape({
    taskId: isString, type: isString, label: isString,
    status: isOneOf("queued", "running", "done", "error", "cancelled"),
    total: isNumber, processed: isNumber, ok: isNumber, fail: isNumber,
  })),
});

export function runWebAccountScripts(input: WebAccountScriptsInput, onProgress?: (value: AccountTaskProgressDTO) => void, signal?: AbortSignal): Promise<AccountBatchResultDTO> {
  const payload: WebAccountScriptsInput = {
    ...input,
    async: input.async ?? true,
    scope: input.scope ?? (input.all ? "pending" : "ids"),
  };
  if (payload.async !== false) {
    return runWebAccountScriptsAsync(payload, onProgress, signal);
  }
  return runAccountTask("/api/admin/v1/accounts/web/run-scripts", payload, ["succeeded", "failed"], onProgress, signal);
}

async function runWebAccountScriptsAsync(
  input: WebAccountScriptsInput,
  onProgress?: (value: AccountTaskProgressDTO) => void,
  signal?: AbortSignal,
): Promise<AccountBatchResultDTO> {
  const result = await runJSONAdminTask("/api/admin/v1/accounts/web/run-scripts", input, onProgress, signal);
  return { succeeded: num(result.succeeded, num(result.ok)), failed: num(result.failed, num(result.fail)) };
}

async function runJSONAdminTask(
  path: string,
  body: object,
  onProgress?: (value: AccountTaskProgressDTO) => void,
  signal?: AbortSignal,
): Promise<Record<string, unknown>> {
  const started = await apiRequest(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body,
    signal,
  }, decodeAdminTaskAccepted);
  return pollAdminTaskResult(started.taskId, onProgress, signal);
}

export function getAdminTask(taskId: string, signal?: AbortSignal): Promise<AdminTaskSnapshotDTO> {
  return apiRequest(`/api/admin/v1/tasks/${encodeURIComponent(taskId)}`, { method: "GET", signal }, decodeAdminTaskSnapshot);
}

export async function listActiveAdminTasks(signal?: AbortSignal): Promise<AdminTaskSnapshotDTO[]> {
  const value = await apiRequest("/api/admin/v1/tasks", { method: "GET", signal }, decodeAdminTaskList);
  return value.tasks.map((item) => decodeAdminTaskSnapshot(item));
}

export function cancelAdminTask(taskId: string, signal?: AbortSignal): Promise<AdminTaskSnapshotDTO> {
  return apiRequest(`/api/admin/v1/tasks/${encodeURIComponent(taskId)}/cancel`, { method: "POST", signal }, decodeAdminTaskSnapshot);
}

async function pollAdminTaskResult(
  taskId: string,
  onProgress?: (value: AccountTaskProgressDTO) => void,
  signal?: AbortSignal,
): Promise<Record<string, unknown>> {
  for (;;) {
    if (signal?.aborted) {
      try { await cancelAdminTask(taskId); } catch { /* ignore */ }
      throw new DOMException("Aborted", "AbortError");
    }
    const snap = await getAdminTask(taskId, signal);
    const phase = snap.phase === "converting" || snap.phase === "syncing" || snap.phase === "importing"
      ? snap.phase
      : undefined;
    onProgress?.({ completed: snap.processed, total: Math.max(snap.total, snap.processed), phase });
    if (snap.status === "done") {
      return {
        ok: snap.ok,
        fail: snap.fail,
        ...(snap.result ?? {}),
      };
    }
    if (snap.status === "error") {
      throw new Error(snap.error || "任务失败");
    }
    if (snap.status === "cancelled") {
      throw new DOMException("Aborted", "AbortError");
    }
    await sleep(500, signal);
  }
}

function num(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new DOMException("Aborted", "AbortError"));
      return;
    }
    const timer = window.setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      window.clearTimeout(timer);
      reject(new DOMException("Aborted", "AbortError"));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

function appendImportOptions(body: FormData, options?: AccountImportOptions): void {
  if (options?.autoSyncConsole !== undefined) {
    body.append("autoSyncConsole", options.autoSyncConsole ? "true" : "false");
  }
  if (options?.trustedSource !== undefined) {
    body.append("trustedSource", options.trustedSource ? "true" : "false");
  }
}

async function runImportAdminTask(path: string, body: FormData, onProgress?: (value: AccountTaskProgressDTO) => void, signal?: AbortSignal): Promise<AccountImportResultDTO> {
  body.append("async", "true");
  const started = await apiRequest(path, {
    method: "POST",
    headers: { Accept: "application/json" },
    body,
    signal,
  }, decodeAdminTaskAccepted);
  const result = await pollAdminTaskResult(started.taskId, onProgress, signal);
  return {
    created: num(result.created),
    updated: num(result.updated),
    synced: num(result.synced),
    syncFailed: num(result.syncFailed),
    consoleCreated: num(result.consoleCreated),
    consoleUpdated: num(result.consoleUpdated),
    consoleFailed: num(result.consoleFailed),
    consoleSkipped: num(result.consoleSkipped),
  };
}

export function importAccounts(files: readonly File[], onProgress?: (value: AccountTaskProgressDTO) => void, signal?: AbortSignal): Promise<AccountImportResultDTO> {
  const body = new FormData();
  files.forEach((file) => body.append("files", file, file.name));
  return runImportAdminTask("/api/admin/v1/accounts/import", body, onProgress, signal);
}

export function importWebAccounts(files: readonly File[], onProgress?: (value: AccountTaskProgressDTO) => void, signal?: AbortSignal, options?: AccountImportOptions): Promise<AccountImportResultDTO> {
  const body = new FormData();
  files.forEach((file) => body.append("files", file, file.name));
  appendImportOptions(body, options);
  return runImportAdminTask("/api/admin/v1/accounts/web/import", body, onProgress, signal);
}

export function importConsoleAccounts(files: readonly File[], onProgress?: (value: AccountTaskProgressDTO) => void, signal?: AbortSignal): Promise<AccountImportResultDTO> {
  const body = new FormData();
  files.forEach((file) => body.append("files", file, file.name));
  return runImportAdminTask("/api/admin/v1/accounts/console/import", body, onProgress, signal);
}

export function fetchCLIPoolSnapshot(): Promise<CLIPoolSnapshotDTO> {
  return apiRequest("/api/admin/v1/accounts/cli-pool-snapshot", { method: "GET" }, createObjectDecoder<CLIPoolSnapshotDTO>("cli pool snapshot", {
    readyTotal: isNumber,
    unprovenReady: isNumber,
    unprovenCap: isNumber,
    target: isNumber,
    readyByBucket: isRecordOf(isNumber),
    updatedAt: isString,
  }));
}

export function updateBuildCLITrustedSource(id: string, trustedSource: boolean): Promise<AccountDTO> {
  return apiRequest(`/api/admin/v1/accounts/${id}/cli-profile`, { method: "PATCH", body: { trustedSource } }, decodeAccount);
}

export function refreshAccountQuota(id: string): Promise<AccountDTO> {
  return apiRequest(`/api/admin/v1/accounts/${id}/refresh-quota`, { method: "POST" }, decodeAccount);
}

export function exportAccounts(provider: AccountProvider): Promise<Blob> {
  return apiDownload(`/api/admin/v1/accounts/export?provider=${encodeURIComponent(provider)}`);
}

export function updateAccountsEnabled(ids: string[], enabled: boolean, provider: AccountProvider): Promise<{ updated: number }> {
  return apiRequest("/api/admin/v1/accounts/batch", { method: "PATCH", body: { ids, enabled, provider } }, decodeCountResult<{ updated: number }>("updated"));
}

export function refreshAccountsQuota(ids: string[], provider: AccountProvider): Promise<{ succeeded: number; failed: number }> {
  return apiRequest("/api/admin/v1/accounts/batch/refresh-quotas", { method: "POST", body: { ids, provider } }, createObjectDecoder("account batch", { succeeded: isNumber, failed: isNumber }));
}

export function refreshAccountsTokens(ids: string[], provider: AccountProvider): Promise<AccountTokenRefreshResultDTO> {
  return apiRequest("/api/admin/v1/accounts/batch/refresh-tokens", { method: "POST", body: { ids, provider } }, createObjectDecoder("account token refresh batch", { succeeded: isNumber, failed: isNumber, skipped: isNumber }));
}

export function cleanupAccounts(provider: AccountProvider, statuses: AccountCleanupStatus[]): Promise<{ deleted: number }> {
  return apiRequest("/api/admin/v1/accounts/cleanup", { method: "POST", body: { provider, statuses } }, decodeCountResult<{ deleted: number }>("deleted"));
}

export function deleteAccounts(ids: string[], provider: AccountProvider): Promise<{ deleted: number }> {
  return apiRequest("/api/admin/v1/accounts", { method: "DELETE", body: { ids, provider } }, decodeCountResult<{ deleted: number }>("deleted"));
}

export function startDeviceAuthorization(): Promise<DeviceSessionDTO> {
  return apiRequest("/api/admin/v1/accounts/device/start", { method: "POST" }, decodeDeviceSession);
}

export function pollDeviceAuthorization(sessionId: string, signal: AbortSignal): Promise<DevicePollDTO> {
  return apiRequest(`/api/admin/v1/accounts/device/${sessionId}/poll`, { method: "POST", signal }, decodeDevicePoll);
}
