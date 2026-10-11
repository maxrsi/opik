import React, { useState } from "react";
import { Button } from "@/ui/button";
import { Input } from "@/ui/input";
import { Label } from "@/ui/label";
import { errorMessage } from "./api";
import { useChangePassword } from "./hooks";

type ChangePasswordFormProps = {
  onDone?: () => void;
};

const MIN_LENGTH = 12;

const ChangePasswordForm: React.FC<ChangePasswordFormProps> = ({ onDone }) => {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const { mutate, isPending, error } = useChangePassword();

  const mismatch = confirm.length > 0 && confirm !== newPassword;
  const tooShort = newPassword.length > 0 && newPassword.length < MIN_LENGTH;

  const onSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    mutate({ currentPassword, newPassword }, { onSuccess: () => onDone?.() });
  };

  return (
    <form onSubmit={onSubmit} className="flex flex-col gap-4">
      <div className="flex flex-col gap-2">
        <Label htmlFor="selfhosted-current-password">Current password</Label>
        <Input
          id="selfhosted-current-password"
          type="password"
          autoComplete="current-password"
          value={currentPassword}
          onChange={(e) => setCurrentPassword(e.target.value)}
        />
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="selfhosted-new-password">New password</Label>
        <Input
          id="selfhosted-new-password"
          type="password"
          autoComplete="new-password"
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
        />
        {tooShort && (
          <span className="comet-body-xs text-muted-slate">
            At least {MIN_LENGTH} characters
          </span>
        )}
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="selfhosted-confirm-password">
          Confirm new password
        </Label>
        <Input
          id="selfhosted-confirm-password"
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
        />
        {mismatch && (
          <span className="comet-body-xs text-destructive">
            Passwords do not match
          </span>
        )}
      </div>
      {error && (
        <div className="comet-body-s text-destructive" role="alert">
          {errorMessage(error, "Could not change the password")}
        </div>
      )}
      <Button
        type="submit"
        disabled={
          isPending ||
          !currentPassword ||
          !newPassword ||
          newPassword !== confirm ||
          tooShort
        }
      >
        {isPending ? "Saving..." : "Change password"}
      </Button>
    </form>
  );
};

export default ChangePasswordForm;
