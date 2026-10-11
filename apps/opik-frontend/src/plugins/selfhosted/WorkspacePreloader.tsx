import React, { useEffect } from "react";
import { Navigate } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import useAppStore, { useSetAppUser } from "@/store/AppStore";
import { DEFAULT_WORKSPACE_NAME } from "@/constants/user";
import { useWorkspaceNameFromURL } from "@/hooks/useWorkspaceNameFromURL";
import Loader from "@/shared/Loader/Loader";
import { Button } from "@/ui/button";
import { ME_KEY } from "./api";
import { useMe } from "./hooks";
import { UNAUTHORIZED_EVENT } from "./init";
import LoginPage from "./LoginPage";
import ChangePasswordPage from "./ChangePasswordPage";

type WorkspacePreloaderProps = {
  children: React.ReactNode;
};

/**
 * Self-hosted session gate: renders the login page without a session, the forced password change when required,
 * and otherwise pins the single workspace ("default") like the OSS preloader does.
 */
const WorkspacePreloader: React.FunctionComponent<WorkspacePreloaderProps> = ({
  children,
}) => {
  const { data: me, isLoading, isError, refetch } = useMe();
  const setAppUser = useSetAppUser();
  const queryClient = useQueryClient();
  const workspaceNameFromURL = useWorkspaceNameFromURL();
  const workspaceName = me?.workspaceName || DEFAULT_WORKSPACE_NAME;

  useEffect(() => {
    const onUnauthorized = () =>
      queryClient.invalidateQueries({ queryKey: [ME_KEY] });
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, [queryClient]);

  useEffect(() => {
    if (me) {
      setAppUser({
        apiKey: me.uiApiKey ?? "",
        userName: me.username,
        email: me.email ?? "",
      });
    }
  }, [me, setAppUser]);

  if (isLoading) {
    return <Loader />;
  }

  if (isError) {
    return (
      <div className="flex h-screen w-screen flex-col items-center justify-center gap-4">
        <div className="comet-body">
          The authentication service is unavailable.
        </div>
        <Button variant="secondary" onClick={() => refetch()}>
          Retry
        </Button>
      </div>
    );
  }

  if (!me) {
    return <LoginPage />;
  }

  if (me.mustChangePassword) {
    return <ChangePasswordPage username={me.username} />;
  }

  useAppStore.getState().setActiveWorkspaceName(workspaceName);

  if (workspaceNameFromURL && workspaceNameFromURL !== workspaceName) {
    return <Navigate to="/$workspaceName" params={{ workspaceName }} />;
  }

  return children;
};

export default WorkspacePreloader;
