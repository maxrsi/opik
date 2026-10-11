import React, { ReactNode, useMemo } from "react";
import { PermissionsProvider as BasePermissionsProvider } from "@/contexts/PermissionsContext";
import { PermissionsContextValue } from "@/types/permissions";
import { useMe } from "./hooks";
import { toFrontendPermissions } from "./permissions";

const PermissionsProvider: React.FC<{ children: ReactNode }> = ({
  children,
}) => {
  const { data: me, isPending } = useMe();

  const value: PermissionsContextValue = useMemo(
    () => ({
      permissions: toFrontendPermissions(me?.permissions ?? []),
      isPending,
    }),
    [me?.permissions, isPending],
  );

  return (
    <BasePermissionsProvider value={value}>{children}</BasePermissionsProvider>
  );
};

export default PermissionsProvider;
