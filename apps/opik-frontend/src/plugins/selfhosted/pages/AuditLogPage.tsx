import React, { useState } from "react";
import { Button } from "@/ui/button";
import { Input } from "@/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/ui/table";
import Loader from "@/shared/Loader/Loader";
import { AUTH_API_BASE_URL, errorMessage } from "../api";
import { AuditFilters, auditQueryString, useAuditLogs, useMe } from "../hooks";
import { SELFHOSTED_PERMISSIONS } from "../types";
import { Forbidden, PageShell, formatTime } from "./common";

const ANY = "any";
const PAGE_SIZE = 50;

const RANGES: Record<string, number> = {
  "1d": 1,
  "7d": 7,
  "30d": 30,
  "90d": 90,
  "180d": 180,
};

const AuditLogPage: React.FC = () => {
  const { data: me } = useMe();
  const canView = !!me?.permissions.includes(
    SELFHOSTED_PERMISSIONS.AUDIT_LOG_VIEW,
  );
  const [range, setRange] = useState("7d");
  const [actor, setActor] = useState("");
  const [action, setAction] = useState("");
  const [outcome, setOutcome] = useState(ANY);
  const [source, setSource] = useState(ANY);
  const [page, setPage] = useState(1);

  const [now] = useState(() => Date.now());
  const baseFilters: Omit<AuditFilters, "page" | "size"> = {
    from: new Date(now - RANGES[range] * 24 * 3600 * 1000).toISOString(),
    to: new Date(now).toISOString(),
    actor: actor.trim() || undefined,
    action: action.trim() || undefined,
    outcome: outcome === ANY ? undefined : outcome,
    source: source === ANY ? undefined : source,
  };
  const { data, isPending, error } = useAuditLogs({
    ...baseFilters,
    page,
    size: PAGE_SIZE,
  });

  if (!canView) {
    return <Forbidden />;
  }

  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;
  const resetPage =
    <T,>(setter: (value: T) => void) =>
    (value: T) => {
      setter(value);
      setPage(1);
    };

  return (
    <PageShell
      title="Audit log"
      description="Write operations, sign-ins and permission denials. Retained for 180 days."
      actions={
        <Button variant="outline" asChild>
          <a
            href={`${AUTH_API_BASE_URL}/audit-logs?${auditQueryString(
              baseFilters,
            )}&format=csv`}
          >
            Export CSV
          </a>
        </Button>
      }
    >
      <div className="flex flex-wrap items-center gap-2">
        <Select value={range} onValueChange={resetPage(setRange)}>
          <SelectTrigger className="h-8 w-28">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {Object.keys(RANGES).map((key) => (
              <SelectItem key={key} value={key}>
                Last {key}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Input
          className="h-8 w-44"
          placeholder="Actor"
          value={actor}
          onChange={(e) => resetPage(setActor)(e.target.value)}
        />
        <Input
          className="h-8 w-56"
          placeholder="Action (e.g. auth.login, traces.create)"
          value={action}
          onChange={(e) => resetPage(setAction)(e.target.value)}
        />
        <Select value={outcome} onValueChange={resetPage(setOutcome)}>
          <SelectTrigger className="h-8 w-36">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ANY}>Any outcome</SelectItem>
            <SelectItem value="success">Success</SelectItem>
            <SelectItem value="failure">Failure</SelectItem>
            <SelectItem value="denied">Denied</SelectItem>
          </SelectContent>
        </Select>
        <Select value={source} onValueChange={resetPage(setSource)}>
          <SelectTrigger className="h-8 w-36">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ANY}>Any source</SelectItem>
            <SelectItem value="backend">opik-backend</SelectItem>
            <SelectItem value="opik-auth">opik-auth</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {error && (
        <div className="comet-body-s text-destructive">
          {errorMessage(error)}
        </div>
      )}
      {isPending ? (
        <Loader />
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Time</TableHead>
              <TableHead>Actor</TableHead>
              <TableHead>Action</TableHead>
              <TableHead>Outcome</TableHead>
              <TableHead>Request</TableHead>
              <TableHead>Resource</TableHead>
              <TableHead>Client IP</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {(data?.content ?? []).length === 0 && (
              <TableRow>
                <TableCell colSpan={7} className="text-center text-muted-slate">
                  No audit events
                </TableCell>
              </TableRow>
            )}
            {(data?.content ?? []).map((item) => (
              <TableRow key={item.id}>
                <TableCell className="whitespace-nowrap">
                  {formatTime(item.eventTime)}
                </TableCell>
                <TableCell>
                  <div>{item.actor || "—"}</div>
                  <div className="comet-body-xs text-muted-slate">
                    {item.actorType}
                  </div>
                </TableCell>
                <TableCell>
                  <code className="comet-body-xs">{item.action}</code>
                </TableCell>
                <TableCell className="capitalize">{item.outcome}</TableCell>
                <TableCell>
                  <div className="comet-body-xs">
                    {item.httpMethod} {item.status || ""}
                  </div>
                  <div
                    className="comet-body-xs max-w-[280px] truncate text-muted-slate"
                    title={item.path}
                  >
                    {item.route || item.path}
                  </div>
                </TableCell>
                <TableCell>
                  <div className="comet-body-xs">{item.resourceType}</div>
                  <div className="comet-body-xs max-w-[220px] truncate text-muted-slate">
                    {item.resourceId}
                  </div>
                </TableCell>
                <TableCell className="comet-body-xs">{item.clientIp}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      <div className="flex items-center justify-end gap-2 pb-6">
        <span className="comet-body-s text-muted-slate">
          {data?.total ?? 0} events · page {page} / {totalPages}
        </span>
        <Button
          size="sm"
          variant="outline"
          disabled={page <= 1}
          onClick={() => setPage(page - 1)}
        >
          Previous
        </Button>
        <Button
          size="sm"
          variant="outline"
          disabled={page >= totalPages}
          onClick={() => setPage(page + 1)}
        >
          Next
        </Button>
      </div>
    </PageShell>
  );
};

export default AuditLogPage;
