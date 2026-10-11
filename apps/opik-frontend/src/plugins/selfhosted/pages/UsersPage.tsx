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
import { useToast } from "@/ui/use-toast";
import Loader from "@/shared/Loader/Loader";
import { errorMessage } from "../api";
import {
  CreateUserBody,
  useCreateUser,
  useMe,
  useResetPassword,
  useRoles,
  useUpdateUser,
  useUsers,
} from "../hooks";
import { SELFHOSTED_PERMISSIONS, SelfHostedRole } from "../types";
import { Forbidden, PageShell, SecretBox, formatTime } from "./common";

const RoleSelect: React.FC<{
  roles: SelfHostedRole[];
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
}> = ({ roles, value, onChange, disabled }) => (
  <Select value={value} onValueChange={onChange} disabled={disabled}>
    <SelectTrigger className="h-8 w-36">
      <SelectValue placeholder="Role" />
    </SelectTrigger>
    <SelectContent>
      {roles.map((role) => (
        <SelectItem key={role.id} value={role.id}>
          {role.displayName}
        </SelectItem>
      ))}
    </SelectContent>
  </Select>
);

const CreateUserDialog: React.FC<{
  open: boolean;
  onOpenChange: (open: boolean) => void;
  roles: SelfHostedRole[];
}> = ({ open, onOpenChange, roles }) => {
  const [form, setForm] = useState<CreateUserBody>({
    username: "",
    displayName: "",
    email: "",
    role: "viewer",
    userType: "human",
  });
  const [initialPassword, setInitialPassword] = useState<string | null>(null);
  const { mutate, isPending, error, reset } = useCreateUser();

  const close = () => {
    setInitialPassword(null);
    setForm({
      username: "",
      displayName: "",
      email: "",
      role: "viewer",
      userType: "human",
    });
    reset();
    onOpenChange(false);
  };

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    mutate(form, {
      onSuccess: (data) => {
        if (data.initialPassword) {
          setInitialPassword(data.initialPassword);
        } else {
          close();
        }
      },
    });
  };

  return (
    <Dialog open={open} onOpenChange={(next) => (next ? null : close())}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Add user</DialogTitle>
        </DialogHeader>
        {initialPassword ? (
          <div className="flex flex-col gap-4">
            <SecretBox label="Initial password" value={initialPassword} />
            <p className="comet-body-s text-muted-slate">
              The user must change it at first sign-in.
            </p>
            <DialogFooter>
              <Button onClick={close}>Done</Button>
            </DialogFooter>
          </div>
        ) : (
          <form onSubmit={submit} className="flex flex-col gap-4">
            <div className="flex flex-col gap-2">
              <Label htmlFor="sh-new-username">Username</Label>
              <Input
                id="sh-new-username"
                value={form.username}
                onChange={(e) => setForm({ ...form, username: e.target.value })}
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="sh-new-display">Display name</Label>
              <Input
                id="sh-new-display"
                value={form.displayName}
                onChange={(e) =>
                  setForm({ ...form, displayName: e.target.value })
                }
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="sh-new-email">Email</Label>
              <Input
                id="sh-new-email"
                value={form.email}
                onChange={(e) => setForm({ ...form, email: e.target.value })}
              />
            </div>
            <div className="flex gap-4">
              <div className="flex flex-col gap-2">
                <Label>Role</Label>
                <RoleSelect
                  roles={roles}
                  value={form.role}
                  onChange={(role) => setForm({ ...form, role })}
                />
              </div>
              <div className="flex flex-col gap-2">
                <Label>Type</Label>
                <Select
                  value={form.userType}
                  onValueChange={(userType) =>
                    setForm({
                      ...form,
                      userType: userType as CreateUserBody["userType"],
                    })
                  }
                >
                  <SelectTrigger className="h-8 w-36">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="human">Human</SelectItem>
                    <SelectItem value="service">Service account</SelectItem>
                  </SelectContent>
                </Select>
              </div>
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
              <Button type="submit" disabled={isPending || !form.username}>
                Create
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
};

const RolesTable: React.FC<{ roles: SelfHostedRole[] }> = ({ roles }) => (
  <Table>
    <TableHeader>
      <TableRow>
        <TableHead className="w-40">Role</TableHead>
        <TableHead>Permissions</TableHead>
      </TableRow>
    </TableHeader>
    <TableBody>
      {roles.map((role) => (
        <TableRow key={role.id}>
          <TableCell className="align-top">
            <div className="comet-body-s-accented">{role.displayName}</div>
            <div className="comet-body-xs text-muted-slate">
              {role.description}
            </div>
          </TableCell>
          <TableCell>
            <div className="flex flex-wrap gap-1">
              {role.permissions.map((permission) => (
                <code
                  key={permission}
                  className="comet-body-xs rounded bg-soft-background px-1.5 py-0.5"
                >
                  {permission}
                </code>
              ))}
            </div>
          </TableCell>
        </TableRow>
      ))}
    </TableBody>
  </Table>
);

const UsersPage: React.FC = () => {
  const { data: me } = useMe();
  const canManage = !!me?.permissions.includes(
    SELFHOSTED_PERMISSIONS.USER_MANAGE,
  );
  const { data: users, isPending } = useUsers();
  const { data: roles = [] } = useRoles();
  const { mutate: updateUser } = useUpdateUser();
  const { mutate: resetPassword } = useResetPassword();
  const { toast } = useToast();
  const [createOpen, setCreateOpen] = useState(false);
  const [resetResult, setResetResult] = useState<{
    username: string;
    password: string;
  } | null>(null);

  if (!canManage) {
    return <Forbidden />;
  }
  if (isPending) {
    return <Loader />;
  }

  const onError = (error: unknown) =>
    toast({
      title: "Error",
      description: errorMessage(error),
      variant: "destructive",
    });

  return (
    <PageShell
      title="Users & roles"
      description="Everyone shares one workspace; access is controlled by the workspace role."
      actions={<Button onClick={() => setCreateOpen(true)}>Add user</Button>}
    >
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Username</TableHead>
            <TableHead>Name / email</TableHead>
            <TableHead>Type</TableHead>
            <TableHead>Role</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Last login</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {(users ?? []).map((user) => {
            const self = user.id === me?.userId;
            return (
              <TableRow key={user.id}>
                <TableCell className="comet-body-s-accented">
                  {user.username}
                  {user.mustChangePassword && (
                    <span className="comet-body-xs ml-2 text-muted-slate">
                      (password change pending)
                    </span>
                  )}
                </TableCell>
                <TableCell>
                  <div>{user.displayName || "—"}</div>
                  <div className="comet-body-xs text-muted-slate">
                    {user.email}
                  </div>
                </TableCell>
                <TableCell className="capitalize">{user.userType}</TableCell>
                <TableCell>
                  <RoleSelect
                    roles={roles}
                    value={user.roleId ?? ""}
                    disabled={self}
                    onChange={(role) =>
                      updateUser({ id: user.id, role }, { onError })
                    }
                  />
                </TableCell>
                <TableCell className="capitalize">{user.status}</TableCell>
                <TableCell>{formatTime(user.lastLoginAt)}</TableCell>
                <TableCell className="text-right">
                  <div className="flex justify-end gap-2">
                    {user.userType === "human" && (
                      <Button
                        size="xs"
                        variant="outline"
                        onClick={() =>
                          resetPassword(user.id, {
                            onSuccess: ({ password }) =>
                              setResetResult({
                                username: user.username,
                                password,
                              }),
                            onError,
                          })
                        }
                      >
                        Reset password
                      </Button>
                    )}
                    <Button
                      size="xs"
                      variant={
                        user.status === "active" ? "destructive" : "outline"
                      }
                      disabled={self}
                      onClick={() =>
                        updateUser(
                          {
                            id: user.id,
                            status:
                              user.status === "active" ? "disabled" : "active",
                          },
                          { onError },
                        )
                      }
                    >
                      {user.status === "active" ? "Disable" : "Enable"}
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>

      <h2 className="comet-title-s pt-6">Roles</h2>
      <RolesTable roles={roles} />

      <CreateUserDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        roles={roles}
      />
      <Dialog
        open={!!resetResult}
        onOpenChange={(open) => (open ? null : setResetResult(null))}
      >
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>
              Password reset for {resetResult?.username}
            </DialogTitle>
          </DialogHeader>
          {resetResult && (
            <SecretBox
              label="Temporary password"
              value={resetResult.password}
            />
          )}
          <DialogFooter>
            <Button onClick={() => setResetResult(null)}>Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </PageShell>
  );
};

export default UsersPage;
