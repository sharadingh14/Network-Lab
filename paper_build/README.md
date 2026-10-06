# Manuscript build

Every number in the manuscript and in the response letter is filled in from `../results/*.json`.

```bash
cd paper_build
cp -r ../figures .
python paper_values.py && python static_values.py   # -> values.json
node build.js manuscript_clean.docx manuscript_highlighted.docx
node build_response.js response_to_reviewers.docx
```
The build stops if a value, table or citation key is missing (requires the `docx` npm package).
