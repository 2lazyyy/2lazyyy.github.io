import { defineCollection } from "astro:content";
import { glob } from "astro/loaders";
import { z } from "astro/zod";

const blog = defineCollection({
  loader: glob({
    pattern: "**/*.md",
    base: "./posts",
  }),

  schema: z.preprocess(
    (value) => {
      if (!value || typeof value !== "object") return value;

      const data = value as Record<string, unknown>;
      const categories = data.categories;

      return {
        ...data,
        description: data.description ?? data.title ?? "",
        pubDate: data.pubDate ?? data.date,
        category:
          data.category ??
          (Array.isArray(categories) ? categories[0] : categories) ??
          "Uncategorized",
        author: data.author ?? "2lazy",
      };
    },
    z.object({
      title: z.string(),
      description: z.string(),
      pubDate: z.coerce.date(),
      updatedDate: z.coerce.date().optional(),
      category: z.string(),
      tags: z.array(z.string()).default([]),
      author: z.string(),
      cover: z.string().optional(),
      draft: z.boolean().default(false),
    }),
  ),
});

export const collections = {
  blog,
};