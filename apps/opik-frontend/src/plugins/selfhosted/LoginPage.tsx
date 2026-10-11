import React, { useState } from "react";
import { Button } from "@/ui/button";
import { Input } from "@/ui/input";
import { Label } from "@/ui/label";
import Logo from "@/shared/Logo/Logo";
import { errorMessage } from "./api";
import { useLogin } from "./hooks";

const LoginPage: React.FC = () => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const { mutate, isPending, error } = useLogin();

  const onSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    mutate({ username: username.trim(), password });
  };

  return (
    <div className="flex h-screen w-screen items-center justify-center bg-soft-background">
      <form
        onSubmit={onSubmit}
        className="flex w-[360px] flex-col gap-5 rounded-lg border bg-background p-8 shadow-sm"
        data-testid="selfhosted-login-form"
      >
        <div className="flex justify-center">
          <Logo expanded />
        </div>
        <h1 className="comet-title-s text-center">Sign in to Opik</h1>
        <div className="flex flex-col gap-2">
          <Label htmlFor="selfhosted-username">Username</Label>
          <Input
            id="selfhosted-username"
            autoComplete="username"
            autoFocus
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </div>
        <div className="flex flex-col gap-2">
          <Label htmlFor="selfhosted-password">Password</Label>
          <Input
            id="selfhosted-password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        {error && (
          <div className="comet-body-s text-destructive" role="alert">
            {errorMessage(error, "Login failed")}
          </div>
        )}
        <Button type="submit" disabled={isPending || !username || !password}>
          {isPending ? "Signing in..." : "Sign in"}
        </Button>
      </form>
    </div>
  );
};

export default LoginPage;
