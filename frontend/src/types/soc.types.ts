import { z } from 'zod';

export const SocAskResponseSchema = z.object({
  answer: z.string(),
  sources: z.array(z.string()).optional()
});

export const SocFeedbackSchema = z.object({
  ok: z.boolean().optional()
});

export type SocAskResponse = z.infer<typeof SocAskResponseSchema>;
export type SocFeedback = z.infer<typeof SocFeedbackSchema>;
