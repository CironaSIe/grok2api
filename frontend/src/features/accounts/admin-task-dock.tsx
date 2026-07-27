import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Loader2, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import { cancelAdminTask, listActiveAdminTasks, type AdminTaskSnapshotDTO } from "@/features/accounts/accounts-api";
import { cn } from "@/shared/lib/cn";

type Props = {
  className?: string;
};

export function AdminTaskDock({ className }: Props) {
  const { t } = useTranslation();
  const query = useQuery({
    queryKey: ["admin-tasks", "active"],
    queryFn: ({ signal }) => listActiveAdminTasks(signal),
    refetchInterval: (current) => {
      const tasks = current.state.data ?? [];
      return tasks.length > 0 ? 1500 : 8000;
    },
    staleTime: 1000,
  });
  const tasks = query.data ?? [];
  if (tasks.length === 0) {
    return null;
  }
  return (
    <div className={cn("rounded-lg border bg-card/80 p-3 shadow-sm", className)}>
      <div className="mb-2 flex items-center justify-between gap-2">
        <p className="text-xs font-medium text-muted-foreground">{t("adminTasks.dockTitle", { count: tasks.length })}</p>
        <Loader2 className="size-3.5 animate-spin text-muted-foreground" />
      </div>
      <div className="space-y-2">
        {tasks.map((task) => (
          <TaskRow key={task.taskId} task={task} onCancel={() => void query.refetch()} />
        ))}
      </div>
    </div>
  );
}

function TaskRow({ task, onCancel }: { task: AdminTaskSnapshotDTO; onCancel: () => void }) {
  const { t } = useTranslation();
  const total = Math.max(task.total, task.processed, 1);
  const pct = Math.min(100, Math.round((task.processed / total) * 100));
  return (
    <div className="flex items-start gap-3 rounded-md bg-muted/40 px-3 py-2">
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
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
      </div>
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
    </div>
  );
}
