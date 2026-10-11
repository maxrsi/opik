import React, { useState } from "react";
import { Link } from "@tanstack/react-router";
import {
  Check,
  KeyRound,
  LockKeyhole,
  LogOut,
  ScrollText,
  Users,
} from "lucide-react";
import { Button } from "@/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuPortal,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from "@/ui/dropdown-menu";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/ui/dialog";
import { useThemeOptions } from "@/hooks/useThemeOptions";
import { useActiveWorkspaceName } from "@/store/AppStore";
import ChangePasswordForm from "./ChangePasswordForm";
import { useLogout, useMe } from "./hooks";
import { SELFHOSTED_PERMISSIONS } from "./types";

const UserMenu: React.FC = () => {
  const { data: me } = useMe();
  const { mutate: logout } = useLogout();
  const workspaceName = useActiveWorkspaceName();
  const [passwordOpen, setPasswordOpen] = useState(false);
  const { theme, themeOptions, CurrentIcon, handleThemeSelect } =
    useThemeOptions();

  if (!me) {
    return null;
  }

  const canManageUsers = me.permissions.includes(
    SELFHOSTED_PERMISSIONS.USER_MANAGE,
  );
  const canViewAudit = me.permissions.includes(
    SELFHOSTED_PERMISSIONS.AUDIT_LOG_VIEW,
  );
  const initials = (me.displayName || me.username).slice(0, 2).toUpperCase();

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="outline"
            size="icon-sm"
            className="rounded-full"
            data-testid="selfhosted-user-menu"
          >
            <span className="comet-body-xs-accented">{initials}</span>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-60">
          <DropdownMenuLabel>
            <div className="comet-body-s-accented truncate">
              {me.displayName || me.username}
            </div>
            <div className="comet-body-xs capitalize text-muted-slate">
              {me.username} · {me.role}
            </div>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuGroup>
            <DropdownMenuItem asChild className="cursor-pointer">
              <Link
                to="/$workspaceName/account/api-keys"
                params={{ workspaceName }}
              >
                <KeyRound className="mr-2 size-4" />
                My API keys
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem
              className="cursor-pointer"
              onClick={() => setPasswordOpen(true)}
            >
              <LockKeyhole className="mr-2 size-4" />
              Change password
            </DropdownMenuItem>
            <DropdownMenuSub>
              <DropdownMenuSubTrigger className="flex cursor-pointer items-center">
                <CurrentIcon className="mr-2 size-4" />
                <span>Theme</span>
              </DropdownMenuSubTrigger>
              <DropdownMenuPortal>
                <DropdownMenuSubContent>
                  {themeOptions.map(({ value, label, icon: Icon }) => (
                    <DropdownMenuItem
                      key={value}
                      className="cursor-pointer"
                      onClick={() => handleThemeSelect(value)}
                    >
                      <div className="relative flex w-full items-center pl-6">
                        {theme === value && (
                          <Check className="absolute left-0 size-4" />
                        )}
                        <Icon className="mr-2 size-4" />
                        <span>{label}</span>
                      </div>
                    </DropdownMenuItem>
                  ))}
                </DropdownMenuSubContent>
              </DropdownMenuPortal>
            </DropdownMenuSub>
          </DropdownMenuGroup>
          {(canManageUsers || canViewAudit) && (
            <>
              <DropdownMenuSeparator />
              <DropdownMenuGroup>
                {canManageUsers && (
                  <DropdownMenuItem asChild className="cursor-pointer">
                    <Link
                      to="/$workspaceName/admin/users"
                      params={{ workspaceName }}
                    >
                      <Users className="mr-2 size-4" />
                      Users & roles
                    </Link>
                  </DropdownMenuItem>
                )}
                {canManageUsers && (
                  <DropdownMenuItem asChild className="cursor-pointer">
                    <Link
                      to="/$workspaceName/admin/api-keys"
                      params={{ workspaceName }}
                    >
                      <KeyRound className="mr-2 size-4" />
                      All API keys
                    </Link>
                  </DropdownMenuItem>
                )}
                {canViewAudit && (
                  <DropdownMenuItem asChild className="cursor-pointer">
                    <Link
                      to="/$workspaceName/admin/audit"
                      params={{ workspaceName }}
                    >
                      <ScrollText className="mr-2 size-4" />
                      Audit log
                    </Link>
                  </DropdownMenuItem>
                )}
              </DropdownMenuGroup>
            </>
          )}
          <DropdownMenuSeparator />
          <DropdownMenuItem
            className="cursor-pointer"
            onClick={() => logout()}
            data-testid="selfhosted-logout"
          >
            <LogOut className="mr-2 size-4" />
            Sign out
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      <Dialog open={passwordOpen} onOpenChange={setPasswordOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Change password</DialogTitle>
          </DialogHeader>
          <ChangePasswordForm onDone={() => setPasswordOpen(false)} />
        </DialogContent>
      </Dialog>
    </>
  );
};

export default UserMenu;
