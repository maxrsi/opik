import React, { useState } from "react";
import { Button } from "@/ui/button";
import { Input } from "@/ui/input";
import { Label } from "@/ui/label";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/ui/table";
import { useToast } from "@/ui/use-toast";
import Loader from "@/shared/Loader/Loader";
import { errorMessage } from "../api";
import {
  useAllApiKeys,
  useCreateApiKey,
  useMe,
  useMyApiKeys,
  useRevokeApiKey,
} from "../hooks";
import { SELFHOSTED_PERMISSIONS, SelfHostedApiKey } from "../types";
import { Forbidden, PageShell, SecretBox, formatTime } from "./common";

const CreateKeyDialog: React.FC<{
  open: boolean;
  onOpenChange: (open: boolean) => void;
}> = ({ open, onOpenChange }) => {
  const [name, setName] = useState("");
  const [days, setDays] = useState("");
  const [created, setCreated] = useState<string | null>(null);
  const { mutate, isPending, error, reset } = useCreateApiKey();

  const close = () => {
    setName("");
    setDays("");
    setCreated(null);
    reset();
    onOpenChange(false);
  };

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    mutate(
      {
        name: name.trim(),
        expiresInDays: days ? parseInt(days, 10) : undefined,
      },
      { onSuccess: (data) => setCreated(data.key) },
    );
  };

  return (
    <Dialog open={open} onOpenChange={(next) => (next ? null : close())}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Create API key</DialogTitle>
        </DialogHeader>
        {created ? (
          <div className="flex flex-col gap-4">
            <SecretBox label="API key" value={created} />
            <p className="comet-body-s text-muted-slate">
              Use it as <code>OPIK_API_KEY</code> with{" "}
              <code>OPIK_WORKSPACE=default</code>. It has the same role as your
              account.
            </p>
            <DialogFooter>
              <Button onClick={close}>Done</Button>
            </DialogFooter>
          </div>
        ) : (
          <form onSubmit={submit} className="flex flex-col gap-4">
            <div className="flex flex-col gap-2">
              <Label htmlFor="sh-key-name">Name</Label>
              <Input
                id="sh-key-name"
                value={name}
                placeholder="e.g. ci-pipeline"
                onChange={(e) => setName(e.target.value)}
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="sh-key-days">Expires in (days, optional)</Label>
              <Input
                id="sh-key-days"
                type="number"
                min={1}
                value={days}
                onChange={(e) => setDays(e.target.value)}
              />
            </div>
            {error && (
              <div className="comet-body-s text-destructive">
                {errorMessage(error)}
              </div>
            )}
            <DialogFooter>
              <Button variant="outline" type="button" onClick={close}>
                Cancel
              </Button>
              <Button type="submit" disabled={isPending || !name.trim()}>
                Create
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
};

const KeysTable: React.FC<{
  keys: SelfHostedApiKey[];
  showOwner: boolean;
  onRevoke: (key: SelfHostedApiKey) => void;
}> = ({ keys, showOwner, onRevoke }) => (
  <Table>
    <TableHeader>
      <TableRow>
        <TableHead>Name</TableHead>
        {showOwner && <TableHead>Owner</TableHead>}
        <TableHead>Key</TableHead>
        <TableHead>Created</TableHead>
        <TableHead>Expires</TableHead>
        <TableHead>Last used</TableHead>
        <TableHead>Status</TableHead>
        <TableHead className="text-right">Actions</TableHead>
      </TableRow>
    </TableHeader>
    <TableBody>
      {keys.length === 0 && (
        <TableRow>
          <TableCell
            colSpan={showOwner ? 8 : 7}
            className="text-center text-muted-slate"
          >
            No API keys
          </TableCell>
        </TableRow>
      )}
      {keys.map((key) => (
        <TableRow key={key.id}>
          <TableCell className="comet-body-s-accented">{key.name}</TableCell>
          {showOwner && <TableCell>{key.username}</TableCell>}
          <TableCell>
            <code className="comet-body-xs">{key.keyPrefix}…</code>
          </TableCell>
          <TableCell>{formatTime(key.createdAt)}</TableCell>
          <TableCell>{formatTime(key.expiresAt)}</TableCell>
          <TableCell>{formatTime(key.lastUsedAt)}</TableCell>
          <TableCell>{key.revokedAt ? "Revoked" : "Active"}</TableCell>
          <TableCell className="text-right">
            {!key.revokedAt && (
              <Button
                size="xs"
                variant="destructive"
                onClick={() => onRevoke(key)}
              >
                Revoke
              </Button>
            )}
          </TableCell>
        </TableRow>
      ))}
    </TableBody>
  </Table>
);

const ApiKeysPage: React.FC<{ scope: "me" | "all" }> = ({ scope }) => {
  const { data: me } = useMe();
  const isAdmin = !!me?.permissions.includes(
    SELFHOSTED_PERMISSIONS.USER_MANAGE,
  );
  const mine = useMyApiKeys();
  const all = useAllApiKeys();
  const { mutate: revoke } = useRevokeApiKey(scope);
  const { toast } = useToast();
  const [createOpen, setCreateOpen] = useState(false);

  if (scope === "all" && !isAdmin) {
    return <Forbidden />;
  }
  const query = scope === "all" ? all : mine;
  if (query.isPending) {
    return <Loader />;
  }

  const onRevoke = (key: SelfHostedApiKey) => {
    if (!window.confirm(`Revoke API key "${key.name}"?`)) {
      return;
    }
    revoke(key.id, {
      onError: (error) =>
        toast({
          title: "Error",
          description: errorMessage(error),
          variant: "destructive",
        }),
    });
  };

  // UI-internal keys (kind=session) are created per browser session; hide them from the user list.
  const keys = (query.data ?? []).filter((key) => key.kind !== "session");

  return (
    <PageShell
      title={scope === "all" ? "All API keys" : "My API keys"}
      description={
        scope === "all"
          ? "API keys of every user. Revoking takes effect within the backend's credential cache TTL."
          : "Keys for the Opik SDK / REST API. A key acts with your role."
      }
      actions={
        scope === "me" ? (
          <Button onClick={() => setCreateOpen(true)}>Create API key</Button>
        ) : null
      }
    >
      <KeysTable keys={keys} showOwner={scope === "all"} onRevoke={onRevoke} />
      <CreateKeyDialog open={createOpen} onOpenChange={setCreateOpen} />
    </PageShell>
  );
};

export const MyApiKeysPage: React.FC = () => <ApiKeysPage scope="me" />;
export const AllApiKeysPage: React.FC = () => <ApiKeysPage scope="all" />;

export default ApiKeysPage;
