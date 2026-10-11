import React from "react";
import Logo from "@/shared/Logo/Logo";
import { Button } from "@/ui/button";
import ChangePasswordForm from "./ChangePasswordForm";
import { useLogout } from "./hooks";

/** Shown instead of the app while the user must change an initial / reset password. */
const ChangePasswordPage: React.FC<{ username: string }> = ({ username }) => {
  const { mutate: logout } = useLogout();

  return (
    <div className="flex h-screen w-screen items-center justify-center bg-soft-background">
      <div className="flex w-[400px] flex-col gap-5 rounded-lg border bg-background p-8 shadow-sm">
        <div className="flex justify-center">
          <Logo expanded />
        </div>
        <h1 className="comet-title-s text-center">Set a new password</h1>
        <p className="comet-body-s text-center text-muted-slate">
          {username}, your password was set by an administrator. Choose a new
          one to continue.
        </p>
        <ChangePasswordForm />
        <Button variant="ghost" size="sm" onClick={() => logout()}>
          Sign out
        </Button>
      </div>
    </div>
  );
};

export default ChangePasswordPage;
