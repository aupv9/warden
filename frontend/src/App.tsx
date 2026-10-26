import { useQuery } from "@tanstack/react-query";
import { api } from "./api/client";
import { userManager } from "./auth/oidc";

interface Me {
  sub: string;
  email: string | null;
  name: string | null;
  mfa: boolean;
}

export function App() {
  const me = useQuery({ queryKey: ["me"], queryFn: () => api<Me>("/me"), retry: false });

  if (me.isPending) return <p>Loading…</p>;
  if (me.isError)
    return (
      <main>
        <h1>Warden</h1>
        <button onClick={() => void userManager.signinRedirect()}>Đăng nhập / Sign in</button>
      </main>
    );
  return (
    <main>
      <h1>Warden</h1>
      <p>
        {me.data.name ?? me.data.email} {me.data.mfa ? "· MFA" : ""}
      </p>
    </main>
  );
}
