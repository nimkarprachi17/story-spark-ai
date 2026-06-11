import { GoogleGenerativeAI } from "@google/generative-ai";
import { GEMINI_MODEL } from "../../../services/ai.service";

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY as string);

export const enhancePromptWithGemini = async (
  prompt: string,
  signal?: AbortSignal,
  compressedContext?: string
): Promise<string> => {
  const model = genAI.getGenerativeModel({ model: GEMINI_MODEL });

  const metaPrompt = `You are a creative writing assistant.

Use the following story context if available:

${compressedContext ?? "No previous context"}

Rewrite the following story prompt to be more vivid, specific, and engaging.
Add a character name, setting details, and a central conflict.

Return ONLY the enhanced prompt, nothing else.

Prompt: ${prompt}`;

  const resultPromise = model.generateContent(metaPrompt);

  const result = signal
    ? await Promise.race([
        resultPromise,
        new Promise<never>((_, reject) =>
          signal.addEventListener("abort", () =>
            reject(new Error("Generation aborted"))
          )
        ),
      ])
    : await resultPromise;

  const text = (result as Awaited<typeof resultPromise>)
    .response.text()
    .trim();

  return text;
};