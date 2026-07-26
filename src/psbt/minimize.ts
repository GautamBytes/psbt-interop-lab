import { applyPsbtMutations, type PsbtMutationRecipe } from "./mutation.js";

export type MutationPredicate = (mutatedPsbt: string) => boolean | Promise<boolean>;

async function reproduces(
  originalPsbt: string,
  recipes: readonly PsbtMutationRecipe[],
  predicate: MutationPredicate,
): Promise<boolean> {
  try {
    return await predicate(applyPsbtMutations(originalPsbt, recipes));
  } catch {
    return false;
  }
}

async function removeRedundantRecipes(
  originalPsbt: string,
  recipes: readonly PsbtMutationRecipe[],
  predicate: MutationPredicate,
): Promise<PsbtMutationRecipe[]> {
  const minimized = [...recipes];
  let index = 0;
  while (index < minimized.length) {
    const candidate = [...minimized.slice(0, index), ...minimized.slice(index + 1)];
    if (candidate.length > 0 && (await reproduces(originalPsbt, candidate, predicate))) {
      minimized.splice(index, 1);
    } else {
      index += 1;
    }
  }
  return minimized;
}

function valueHex(recipe: PsbtMutationRecipe): string | undefined {
  return recipe.kind === "append-bytes" ||
    recipe.kind === "replace-value" ||
    recipe.kind === "set-entry"
    ? recipe.valueHex
    : undefined;
}

function withValueHex(recipe: PsbtMutationRecipe, replacement: string): PsbtMutationRecipe {
  if (
    recipe.kind === "append-bytes" ||
    recipe.kind === "replace-value" ||
    recipe.kind === "set-entry"
  ) {
    return { ...recipe, valueHex: replacement };
  }
  return recipe;
}

async function shrinkValues(
  originalPsbt: string,
  recipes: PsbtMutationRecipe[],
  predicate: MutationPredicate,
): Promise<PsbtMutationRecipe[]> {
  const minimized = [...recipes];
  for (const [index, recipe] of minimized.entries()) {
    let current = valueHex(recipe);
    if (!current || current.length <= 2) continue;
    while (current.length > 2) {
      const candidateValue = current.slice(Math.floor(current.length / 4) * 2);
      const candidate = [...minimized];
      candidate[index] = withValueHex(recipe, candidateValue);
      if (!(await reproduces(originalPsbt, candidate, predicate))) break;
      current = candidateValue;
      minimized[index] = candidate[index] as PsbtMutationRecipe;
    }
  }
  return minimized;
}

export async function minimizeMutationRecipes(
  originalPsbt: string,
  recipes: readonly PsbtMutationRecipe[],
  predicate: MutationPredicate,
): Promise<readonly PsbtMutationRecipe[]> {
  if (recipes.length === 0 || !(await reproduces(originalPsbt, recipes, predicate))) {
    throw new TypeError("Original mutation recipe does not reproduce the differential predicate");
  }
  const reduced = await removeRedundantRecipes(originalPsbt, recipes, predicate);
  return shrinkValues(originalPsbt, reduced, predicate);
}
