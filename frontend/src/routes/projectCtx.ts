import { createContext, useContext } from "react";
import type { Project } from "../api/types";

// The project shown by ProjectLayout, for its tabs. In its own module so each tab's chunk
// doesn't pull in the layout (and the issue list it renders).
export const ProjectContext = createContext<Project | null>(null);

export function useProjectCtx(): Project {
  const p = useContext(ProjectContext);
  if (!p) throw new Error("useProjectCtx outside ProjectLayout");
  return p;
}
