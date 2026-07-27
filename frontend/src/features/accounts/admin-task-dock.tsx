import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { ChevronDown, ChevronRight, Loader2, X } from "lucide-react";
import { useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cancelAdminTask, decodeBuildConversionFailures, listRecentAdminTasks, type AdminTaskSnapshotDTO } from "@/features/accounts/accounts-api";
import { cn } from "@/shared/lib/cn";

type Props = {
  className?: string;
};

export function AdminTaskDock({ className }: Props) {
  const { t } = useTranslation();
  const query = useQuery({
    queryKey: ["admin-tasks", "recent"],
    queryFn: ({ signal }) => listRecentAdminTasks(signal),
    refetchInterval: (current) => {
      const tasks = current.state.data ?? [];
      if (tasks.length === 0) return false;
      return tasks.some((task) => task.status === "running" || task.status === "queued") ? 1500 : 8000;
    },
    staleTime: 1000,
  });
  const tasks = query.data ?? [];
  if (tasks.length === 0) {
    return null;
  }
  const hasRunning = tasks.some((task) => task.status === "running" || task.status === "queued");
  return (
    <div className={cn("rounded-lg border bg-card/80 p-3 shadow-sm", className)}>
      <div className="mb-2 flex items-center justify-between gap-2">
        <p className="text-xs font-medium text-muted-foreground">{t("adminTasks.dockTitle", { count: tasks.length })}</p>
        {hasRunning ? <Loader2 className="size-3.5 animate-spin text-muted-foreground" /> : null}
      </div>
      <div className="space-y-2">
        {tasks.map((task) => (
          <TaskRow key={task.taskId} task={task} onCancel={() => void query.refetch()} />
        ))}
      </div>
    </div>
  );
}

function conversionClassBadgeVariant(classValue: string | undefined): "default" | "secondary" | "destructive" | "outline" {
  switch (classValue) {
    case "sso_dead":
    case "permanent":
    case "bot_contaminated":
      return "destructive";
    case "rate_limited":
      return "secondary";
    case "network_retry":
      return "outline";
    default:
      return "default";
  }
}

function conversionClassLabel(t: ReturnType<typeof useTranslation>["t"], classValue: string | undefined): string {
  switch (classValue) {
    case "sso_dead": return t("accounts.conversionClassSsoDead");
    case "rate_limited": return t("accounts.conversionClassRateLimited");
    case "network_retry": return t("accounts.conversionClassNetworkRetry");
    case "permanent": return t("accounts.conversionClassPermanent");
    case "bot_contaminated": return t("accounts.conversionClassBotContaminated");
    default: return t("accounts.conversionClassUnknown");
  }
}

const terminalStatuses = new Set(["done", "error", "cancelled"]);

function TaskRow({ task, onCancel }: { task: AdminTaskSnapshotDTO; onCancel: () => void }) {
  const { t } = useTranslation();
  const [expanded, setExpanded] = useState(false);
  const total = Math.max(task.total, task.processed, 1);
  const pct = Math.min(100, Math.round((task.processed / total) * 100));
  const isTerminal = terminalStatuses.has(task.status);
  const canExpand = isTerminal && task.fail > 0;
  const failures = canExpand && expanded ? decodeBuildConversionFailures(task.result?.failures) : undefined;
  return (
    <div className="flex items-start gap-3 rounded-md bg-muted/40 px-3 py-2">
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          {canExpand ? (
            <button
              type="button"
              className="shrink-0 text-muted-foreground hover:text-foreground"
              onClick={() => setExpanded((current) => !current)}
            >
              {expanded ? <ChevronDown className="size-3.5" /> : <ChevronRight className="size-3.5" />}
            </button>
          ) : null}
          <p className="truncate text-xs font-medium">{task.label || task.type}</p>
          <span className="rounded bg-background px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">{task.status}</span>
          {task.phase ? <span className="text-[10px] text-muted-foreground">{task.phase}</span> : null}
        </div>
        <div className="h-1.5 overflow-hidden rounded-full bg-background">
          <div className="h-full bg-primary transition-all" style={{ width: `${pct}%` }} />
        </div>
        <p className="font-mono text-[11px] tabular-nums text-muted-foreground">
          {task.processed}/{Math.max(task.total, task.processed)} · ok {task.ok} · fail {task.fail}
        </p>
        {failures && failures.length > 0 ? (
          <div className="space-y-1 pt-1">
            {failures.map((failure) => (
              <div key={failure.accountId} className="flex items-start gap-2 rounded bg-background/50 px-2 py-1">
                <span className="font-mono text-[10px] tabular-nums text-muted-foreground">#{failure.accountId}</span>
                <Badge variant={conversionClassBadgeVariant(failure.class)}>
                  {conversionClassLabel(t, failure.class)}
                </Badge>
                <span className="min-w-0 flex-1 break-all text-[10px] text-muted-foreground">{failure.message}</span>
              </div>
            ))}
          </div>
        ) : null}
      </div>
      {!isTerminal ? (
        <Button
          type="button"
          size="icon"
          variant="ghost"
          className="size-7 shrink-0"
          title={t("adminTasks.cancel")}
          onClick={async () => {
            try {
              await cancelAdminTask(task.taskId);
            } catch {
              /* ignore */
            }
            onCancel();
          }}
        >
          <X className="size-3.5" />
        </Button>
      ) : null}
    </div>
  );
}
