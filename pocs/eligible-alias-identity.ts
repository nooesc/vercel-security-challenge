export interface EligibleAliasIdentityInput {
  token: string;
  expectedEmail: string;
  expectedTeamId: string;
  expectedProjectId: string;
  manualEmailConfirmation?: string | undefined;
  fetchImpl?: typeof fetch | undefined;
}

export interface EligibleAliasIdentityProof {
  email: string;
  teamId: string;
  projectId: string;
  method: "v2-user-email" | "manual-email-plus-exact-team-project-api";
}

function object(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

export async function verifyEligibleAliasToken(
  input: EligibleAliasIdentityInput,
): Promise<EligibleAliasIdentityProof> {
  const fetchImpl = input.fetchImpl ?? fetch;
  const headers = { Authorization: `Bearer ${input.token}` };
  const userResponse = await fetchImpl("https://api.vercel.com/v2/user", {
    headers,
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
  if (userResponse.ok) {
    const payload = object(await userResponse.json());
    const user = object(payload.user);
    if (user.email !== input.expectedEmail) {
      throw new Error("Vercel token is not authenticated as the required HackerOne alias");
    }
    return {
      email: input.expectedEmail,
      teamId: input.expectedTeamId,
      projectId: input.expectedProjectId,
      method: "v2-user-email",
    };
  }
  if (userResponse.status !== 401 && userResponse.status !== 403) {
    throw new Error(`Vercel alias verification returned ${userResponse.status}`);
  }
  if (input.manualEmailConfirmation !== input.expectedEmail) {
    throw new Error("scoped Sandbox token requires the exact manual HackerOne alias confirmation");
  }
  const [teamResponse, projectResponse] = await Promise.all([
    fetchImpl(`https://api.vercel.com/v2/teams/${input.expectedTeamId}`, {
      headers,
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
    }),
    fetchImpl(
      `https://api.vercel.com/v9/projects/${input.expectedProjectId}?teamId=${input.expectedTeamId}`,
      { headers, redirect: "error", signal: AbortSignal.timeout(10_000) },
    ),
  ]);
  if (!teamResponse.ok || !projectResponse.ok) {
    throw new Error(`scoped Vercel identity proof failed (team=${teamResponse.status}, project=${projectResponse.status})`);
  }
  const team = object(await teamResponse.json());
  const project = object(await projectResponse.json());
  if (team.id !== input.expectedTeamId || project.id !== input.expectedProjectId) {
    throw new Error("scoped Vercel identity proof returned the wrong team or project");
  }
  return {
    email: input.expectedEmail,
    teamId: input.expectedTeamId,
    projectId: input.expectedProjectId,
    method: "manual-email-plus-exact-team-project-api",
  };
}
