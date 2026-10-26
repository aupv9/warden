import { lazy } from "react";
import type { ComponentType, LazyExoticComponent } from "react";

// Route-level code splitting: each page is its own chunk, loaded on first visit, so the entry
// chunk holds only the shell (auth, layout, navigation). Every loader is kept so tests (and,
// if we want, idle-time prefetching) can load them all up front.

const loaders: (() => Promise<unknown>)[] = [];

export function lazyRoute<M, K extends keyof M>(load: () => Promise<M>, name: K): LazyExoticComponent<ComponentType> {
  loaders.push(load);
  return lazy(async () => ({ default: (await load())[name] as ComponentType }));
}

/** Loads every page chunk (tests render routes with react-dom/server, which can't wait). */
export function preloadRoutes(): Promise<unknown[]> {
  return Promise.all(loaders.map((l) => l()));
}
