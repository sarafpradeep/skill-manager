import { collectionsApi } from "./collections";
import { projectsApi } from "./projects";
import { scannerApi } from "./scanner";
import { skillsApi } from "./skills";

/** Single place the frontend talks to the Rust command layer. */
export const api = { ...skillsApi, ...projectsApi, ...collectionsApi, ...scannerApi };
