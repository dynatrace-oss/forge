module.exports = {
  extends: ["@commitlint/config-conventional"],
  plugins: ["commitlint-plugin-function-rules"],
  rules: {
    "subject-empty": [0],
    "subject-max-length": [0],
    "function-rules/subject-max-length": [
      2,
      "always",
      (parsed) => {
        const ticketNumberRegex =
          /^(?::\w*:|(?:\ud83c[\udf00-\udfff])|(?:\ud83d[\udc00-\ude4f\ude80-\udeff])|[\u2600-\u2B55])?\s?(?:TR-\d+|SIA-\d+|NO-ISSUE)\s[A-Z].*$/;
        const isValid = ticketNumberRegex.test(parsed.header);
        return isValid
          ? [true]
          : [
              false,
              `Commit message should start with an optional gitmoji, a ticket number (e.g. TR-123, SIA-123) or NO-ISSUE followed by a subject case word.`,
            ];
      },
    ],
    "type-empty": [0],
  },
};
