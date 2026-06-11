export interface ICompressedContext {
  characters: string[];
  keyEvents: string[];
  setting: string[];
  compressedText: string;
}

export function contextCompressor(fullStory: string): ICompressedContext {
  if (!fullStory) {
    return {
      characters: [],
      keyEvents: [],
      setting: [],
      compressedText: ""
    };
  }

  const sentences = fullStory.split(/[.!?]+/).map(s => s.trim()).filter(Boolean);

  const characters = new Set<string>();
  const keyEvents: string[] = [];
  const setting = new Set<string>();

  for (const sentence of sentences) {
    // simple heuristic: capitalized words = characters
    const words = sentence.split(" ");

    for (const w of words) {
      if (/^[A-Z][a-z]+$/.test(w)) {
        characters.add(w);
      }
    }

    // event detection (simple rule-based)
    if (
      sentence.includes("killed") ||
      sentence.includes("found") ||
      sentence.includes("discovered") ||
      sentence.includes("fought")
    ) {
      keyEvents.push(sentence);
    }

    // setting detection
    if (
      sentence.includes("forest") ||
      sentence.includes("castle") ||
      sentence.includes("city") ||
      sentence.includes("kingdom")
    ) {
      setting.add(sentence);
    }
  }

  return {
    characters: Array.from(characters),
    keyEvents,
    setting: Array.from(setting),
    compressedText: `
Characters: ${Array.from(characters).join(", ")}
Events: ${keyEvents.slice(0, 5).join(" | ")}
Settings: ${Array.from(setting).join(" | ")}
    `.trim()
  };
}