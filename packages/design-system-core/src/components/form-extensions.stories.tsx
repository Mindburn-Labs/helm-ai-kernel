import type { Story, StoryDefault } from "@ladle/react";
import { useState } from "react";
import {
  Button,
  FieldArray,
  FileField,
  FormField,
  Panel,
  SelectField,
  TextInput,
} from "@helm/design-system-core";

export default {
  title: "Primitives / FormExtensions",
} satisfies StoryDefault;

interface Recipient {
  readonly email: string;
  readonly role: string;
}

const ROLES = ["owner", "approver", "reviewer", "watcher"] as const;

export const FieldArrayRecipients: Story = () => (
  <Panel title="Recipients" kicker="Add, remove, and reorder rows; submit names are dotted.">
    <FieldArray<Recipient>
      name="recipients"
      defaultValue={[
        { email: "alice@helm.example", role: "owner" },
        { email: "bob@helm.example", role: "reviewer" },
      ]}
    >
      {(handle) => (
        <div style={{ display: "grid", gap: 12 }}>
          {handle.items.map((item, i) => (
            <div
              key={item.key}
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 200px auto auto auto",
                gap: 8,
                alignItems: "end",
              }}
            >
              <FormField label="Email">
                <TextInput
                  name={handle.fieldName(i, "email")}
                  defaultValue={item.value.email}
                  placeholder="user@example.com"
                />
              </FormField>
              <FormField label="Role">
                <SelectField
                  name={handle.fieldName(i, "role")}
                  defaultValue={item.value.role}
                  options={ROLES}
                />
              </FormField>
              <Button
                size="sm"
                variant="ghost"
                disabled={i === 0}
                onClick={() => handle.move(i, i - 1)}
                aria-label="Move up"
              >
                ↑
              </Button>
              <Button
                size="sm"
                variant="ghost"
                disabled={i === handle.items.length - 1}
                onClick={() => handle.move(i, i + 1)}
                aria-label="Move down"
              >
                ↓
              </Button>
              <Button
                size="sm"
                variant="danger"
                onClick={() => handle.remove(i)}
                aria-label="Remove"
              >
                ×
              </Button>
            </div>
          ))}
          <div style={{ display: "flex", gap: 8 }}>
            <Button
              size="sm"
              variant="secondary"
              onClick={() => handle.add({ email: "", role: "watcher" })}
            >
              Add recipient
            </Button>
            <Button size="sm" variant="ghost" onClick={() => handle.clear()}>
              Clear
            </Button>
          </div>
        </div>
      )}
    </FieldArray>
  </Panel>
);

interface UploadError {
  readonly code: "size" | "type";
  readonly file: File;
}

export const FileFieldUpload: Story = () => {
  const [files, setFiles] = useState<readonly File[]>([]);
  const [errors, setErrors] = useState<UploadError[]>([]);
  return (
    <Panel
      title="Evidence upload"
      kicker="Drop image/* or .pdf files up to 5 MB. Larger files / wrong types fire onError."
    >
      <FormField label="Evidence" hint="Up to 5 MB per file. images and PDFs only.">
        <FileField
          accept="image/*,.pdf"
          multiple
          maxSize={5 * 1024 * 1024}
          value={files}
          onValueChange={setFiles}
          onError={(error) => setErrors((current) => [...current, error])}
        />
      </FormField>
      {errors.length > 0 ? (
        <ul style={{ marginBlockStart: 12, color: "var(--helm-state-deny-fg)" }}>
          {errors.map((error, i) => (
            <li key={`${error.file.name}-${i}`}>
              {error.code === "size" ? "Too large" : "Wrong type"}: {error.file.name}
            </li>
          ))}
        </ul>
      ) : null}
    </Panel>
  );
};

export const FileFieldSingle: Story = () => (
  <Panel title="Single-file upload" kicker="multiple=false clamps the input to one file.">
    <FormField label="Receipt">
      <FileField accept=".pdf" hint="One PDF only." />
    </FormField>
  </Panel>
);
