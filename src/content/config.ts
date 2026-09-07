import { defineCollection, z } from "astro:content";

const referenceSchema = z.object({
  title: z.string(),
  url: z.string().url(),
  publisher: z.string().optional()
});

const timelineSchema = z.object({
  date: z.string(),
  title: z.string(),
  summary: z.string()
});

const assetSchema = z.object({
  label: z.string(),
  url: z.string(),
  kind: z.enum(["image", "archive", "text", "external"]).default("text")
});

const jsonValueSchema: z.ZodType<string | number | boolean | Record<string, unknown> | unknown[]> = z.lazy(() =>
  z.union([z.string(), z.number(), z.boolean(), z.record(z.string(), jsonValueSchema), z.array(jsonValueSchema)])
);

const selectOptionSchema = z.object({
  label: z.string(),
  value: z.string()
});

const intakeItemFieldSchema = z.object({
  name: z.string(),
  label: z.string(),
  type: z.enum(["text", "textarea", "date", "number", "select", "checkbox"]),
  required: z.boolean().default(false),
  description: z.string().optional(),
  placeholder: z.string().optional(),
  options: z.array(selectOptionSchema).default([]),
  defaultValue: jsonValueSchema.optional()
});

const intakeFieldSchema = z
  .object({
    name: z.string(),
    label: z.string(),
    type: z.enum([
      "text",
      "textarea",
      "date",
      "number",
      "select",
      "checkbox",
      "stringList",
      "objectList",
      "markdownBody",
      "specialRawAnswers"
    ]),
    required: z.boolean().default(false),
    description: z.string().optional(),
    placeholder: z.string().optional(),
    options: z.array(selectOptionSchema).default([]),
    defaultValue: jsonValueSchema.optional(),
    deriveFrom: z.string().optional(),
    outputName: z.string().optional(),
    itemLabel: z.string().optional(),
    addLabel: z.string().optional(),
    rows: z.number().int().positive().optional(),
    fields: z.array(intakeItemFieldSchema).default([])
  })
  .superRefine((field, ctx) => {
    if (field.type === "select" && field.options.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Select fields must declare at least one option."
      });
    }

    if (field.type === "objectList" && field.fields.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Object list fields must declare item fields."
      });
    }

    if (field.type === "specialRawAnswers" && !field.outputName) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "specialRawAnswers fields must declare an outputName."
      });
    }

    if (field.deriveFrom && field.type !== "text") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "deriveFrom is only supported on text fields."
      });
    }
  });

const intakeFieldGroupSchema = z.object({
  label: z.string(),
  description: z.string().optional(),
  fields: z.array(z.string()).min(1)
});

const blog = defineCollection({
  type: "content",
  schema: z.object({
    title: z.string(),
    description: z.string(),
    publishedAt: z.coerce.date(),
    archiveSection: z.enum(["reports", "writeups"]).default("reports"),
    tags: z.array(z.string()).default([]),
    cover: z.string().optional(),
    featured: z.boolean().default(false),
    draft: z.boolean().default(false),
    sourceLabel: z.string().optional(),
    sourceUrl: z.string().url().optional()
  })
});

const actors = defineCollection({
  type: "content",
  schema: z.object({
    name: z.string(),
    aliases: z.array(z.string()).default([]),
    status: z.enum(["active", "tracking", "disrupted", "historic"]),
    origin: z.string(),
    motivation: z.string(),
    targets: z.array(z.string()).default([]),
    firstSeen: z.string(),
    lastSeen: z.string(),
    tools: z.array(z.string()).default([]),
    ttps: z.array(z.string()).default([]),
    tags: z.array(z.string()).default([]),
    timeline: z.array(timelineSchema).default([]),
    references: z.array(referenceSchema).default([]),
    relatedPosts: z.array(z.string()).default([]),
    featured: z.boolean().default(false)
  })
});

const ctfCollections = defineCollection({
  type: "content",
  schema: z.object({
    title: z.string(),
    summary: z.string(),
    status: z.enum(["active", "retired", "archived"]),
    year: z.string(),
    githubUrl: z.string().url().optional(),
    featured: z.boolean().default(false)
  })
});

const ctfChallenges = defineCollection({
  type: "content",
  schema: z.object({
    collection: z.string(),
    title: z.string(),
    difficulty: z.enum(["easy", "medium", "hard"]),
    prompt: z.string(),
    passwordFormat: z.string(),
    assets: z.array(assetSchema).default([]),
    image: z.string().optional(),
    hint: z.string().optional(),
    answerHashes: z.array(z.string()),
    acceptedAliases: z.array(z.string()).default([]),
    order: z.number().int().positive()
  })
});

const intakeTemplates = defineCollection({
  type: "content",
  schema: z
    .object({
      id: z.string(),
      label: z.string(),
      contentType: z.enum(["blog", "actors", "ctfCollections", "ctfChallenges", "tools"]),
      targetPathPattern: z.string(),
      previewPathPattern: z.string(),
      fieldGroups: z.array(intakeFieldGroupSchema).min(1),
      fields: z.array(intakeFieldSchema).min(1),
      defaultValues: z.record(z.string(), jsonValueSchema).default({}),
      frontmatterOrder: z.array(z.string()).default([])
    })
    .superRefine((template, ctx) => {
      const fieldMap = new Map(template.fields.map((field) => [field.name, field]));
      const outputKeys = new Set(
        template.fields
          .filter((field) => field.type !== "markdownBody")
          .map((field) => field.outputName ?? field.name)
      );

      template.fieldGroups.forEach((group, groupIndex) => {
        group.fields.forEach((fieldName, fieldIndex) => {
          if (!fieldMap.has(fieldName)) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              message: `Unknown field "${fieldName}" referenced by fieldGroups.`,
              path: ["fieldGroups", groupIndex, "fields", fieldIndex]
            });
          }
        });
      });

      template.frontmatterOrder.forEach((fieldName, fieldIndex) => {
        if (!outputKeys.has(fieldName)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `Unknown frontmatter key "${fieldName}" in frontmatterOrder.`,
            path: ["frontmatterOrder", fieldIndex]
          });
        }
      });
    })
});

const tools = defineCollection({
  type: "content",
  schema: z.object({
    name: z.string(),
    tagline: z.string(),
    description: z.string(),
    type: z.string(),
    os: z.array(z.string()).default([]),
    version: z.string().default("1.0.0"),
    releaseDate: z.string().optional(),
    icon: z.string().optional(),
    downloadUrl: z.string().url(),
    githubUrl: z.string().url().optional(),
    docsUrl: z.string().url().optional(),
    featured: z.boolean().default(false),
    tags: z.array(z.string()).default([]),
    order: z.number().int().optional()
  })
});

export const collections = {
  blog,
  actors,
  ctfCollections,
  ctfChallenges,
  intakeTemplates,
  tools
};

