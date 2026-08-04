import type { AssessmentProgress, AssessmentStage } from '../../types/assessment';
import { Badge } from '../ui/Badge';
import { ProgressBar } from '../ui/ProgressBar';
import { progressColor, STAGE_LABELS, statusColor } from './assessmentMeta';

interface AssessmentProgressProps {
  progress: AssessmentProgress | null;
  status: string;
  overallPercent: number | null;
}

export function AssessmentProgress({ progress, status, overallPercent }: AssessmentProgressProps) {
  return (
    <div className="space-y-4">
      <div>
        <div className="flex justify-between text-sm mb-1">
          <span className="text-surface-600 dark:text-surface-400">Overall Progress</span>
          <span className="font-medium text-surface-800 dark:text-surface-200">
            {Math.round(overallPercent ?? 0)}%
          </span>
        </div>
        <ProgressBar value={overallPercent ?? 0} color={progressColor(status)} />
      </div>
      {progress && progress.stages.length > 0 ? (
        <div className="space-y-3">
          {progress.stages.map((stage: AssessmentStage) => (
            <div key={stage.stage_name} className="p-3 rounded-lg bg-surface-50 dark:bg-surface-800/50">
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm font-medium text-surface-800 dark:text-surface-200">
                  {STAGE_LABELS[stage.stage_name] || stage.stage_name}
                </span>
                <div className="flex items-center gap-2">
                  <Badge variant={statusColor(stage.status)}>{stage.status}</Badge>
                  <span className="text-xs font-mono text-surface-500">{Math.round(stage.progress)}%</span>
                </div>
              </div>
              <ProgressBar value={stage.progress} color={progressColor(stage.status)} size="sm" />
              {stage.error_message && (
                <p className="text-xs text-critical mt-2">{stage.error_message}</p>
              )}
              {stage.summary && (
                <p className="text-xs text-surface-400 mt-2 font-mono">{JSON.stringify(stage.summary)}</p>
              )}
            </div>
          ))}
        </div>
      ) : (
        <p className="text-sm text-surface-400">
          Pipeline progress is unavailable for this assessment (only visible while running or for in-session scans).
        </p>
      )}
    </div>
  );
}
