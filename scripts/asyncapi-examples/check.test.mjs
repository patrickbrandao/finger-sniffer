// Testes do passo de validação dos examples do asyncapi (task 044). Rodados pelo verify com `node --test`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkExamples, loadDocument, run } from './check.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const ASYNCAPI = join(ROOT, 'eventbus/nats/asyncapi.yaml');

// Cópia temporária do asyncapi fora do repositório, com as refs externas relativas trocadas por absolutas.
function tempCopy(mutate) {
  const dir = mkdtempSync(join(tmpdir(), 'fs-asyncapi-'));
  let text = readFileSync(ASYNCAPI, 'utf8').replaceAll('$ref: "../../', `$ref: "${ROOT}/`);
  text = mutate(text);
  const file = join(dir, 'asyncapi.yaml');
  writeFileSync(file, text);
  return { file, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

const quiet = () => {};

const doc3 = (messages, extra = {}) => ({
  asyncapi: '3.1.0',
  defaultContentType: 'application/json',
  components: { messages, ...extra },
});

const schema = {
  type: 'object',
  required: ['ok'],
  properties: { ok: { type: 'boolean' } },
  additionalProperties: false,
};

test('o asyncapi do repositório passa', async () => {
  const r = checkExamples(await loadDocument(ASYNCAPI));
  assert.ok(r.examples > 0, 'nenhum exemplo encontrado');
  assert.deepEqual(r.failures, []);
});

test('cópia do asyncapi com exemplo inline inválido falha', async () => {
  // Não depende de um exemplo específico do asyncapi real: injeta um exemplo inválido (payload que não é objeto)
  // na primeira mensagem JSON com payload de uma cópia temporária já derreferenciada.
  const doc = await loadDocument(ASYNCAPI);
  const entry = Object.entries(doc.components.messages).find(
    ([, m]) => m.payload && ((m.examples || []).length > 0 || (m.traits || []).some((t) => (t.examples || []).length > 0)),
  );
  assert.ok(entry, 'nenhuma mensagem JSON com exemplos no asyncapi');
  const [id, msg] = entry;
  msg.examples = [...(msg.examples || []), { name: 'injected_invalid', payload: 12345 }];
  const dir = mkdtempSync(join(tmpdir(), 'fs-asyncapi-'));
  const file = join(dir, 'asyncapi.json');
  writeFileSync(file, JSON.stringify(doc));
  try {
    const lines = [];
    assert.equal(await run(file, (l) => lines.push(l)), 1);
    assert.ok(lines.some((l) => l.startsWith(`FALHA ${id}/injected_invalid:`)), lines.join('\n'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('cópia do asyncapi com golden externo inválido falha', async () => {
  // Troca a ref do primeiro golden com envelope por uma cópia temporária com schema_version inválido.
  const text = readFileSync(ASYNCAPI, 'utf8');
  const refs = [...text.matchAll(/\$ref: "\.\.\/\.\.\/([^"#]+\.json)"/g)].map((m) => m[1]);
  const rel = refs.find((r) => 'schema_version' in JSON.parse(readFileSync(join(ROOT, r), 'utf8')));
  assert.ok(rel, 'nenhum golden com envelope referenciado no asyncapi');
  const bad = JSON.parse(readFileSync(join(ROOT, rel), 'utf8'));
  bad.schema_version = 'not-a-version';
  const dir = mkdtempSync(join(tmpdir(), 'fs-golden-'));
  const badFile = join(dir, 'bad.json');
  writeFileSync(badFile, JSON.stringify(bad));
  const { file, cleanup } = tempCopy((t) => t.replace(`$ref: "${ROOT}/${rel}"`, `$ref: "${badFile}"`));
  try {
    const r = checkExamples(await loadDocument(file));
    const hit = r.failures.filter((f) => /schema_version/.test(f.errors));
    assert.equal(hit.length, 1, `${rel}: ${JSON.stringify(r.failures)}`);
  } finally {
    cleanup();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('exemplos de trait aplicado são validados', () => {
  const r = checkExamples(
    doc3({
      Reply: {
        payload: schema,
        traits: [{ examples: [{ name: 'good', payload: { ok: true } }, { name: 'bad', payload: { ok: 1 } }] }],
      },
    }),
  );
  assert.equal(r.examples, 2);
  assert.equal(r.failures.length, 1);
  assert.equal(r.failures[0].example, 'bad');
});

test('mensagem JSON sem exemplo é aviso, não falha', () => {
  const r = checkExamples(doc3({ Empty: { payload: schema } }));
  assert.deepEqual(r.failures, []);
  assert.equal(r.warnings.length, 1);
});

test('mensagem não JSON é ignorada', () => {
  const r = checkExamples(
    doc3({ Bin: { contentType: 'application/octet-stream', payload: { type: 'string' }, examples: [{ payload: 1 }] } }),
  );
  assert.equal(r.examples, 0);
  assert.deepEqual(r.failures, []);
  assert.deepEqual(r.warnings, []);
});

test('content type vem do trait quando a mensagem não define', () => {
  const r = checkExamples({
    asyncapi: '3.1.0',
    components: {
      messages: {
        M: { payload: schema, traits: [{ contentType: 'application/json' }], examples: [{ name: 'x', payload: {} }] },
      },
    },
  });
  assert.equal(r.failures.length, 1);
});

test('documento ilegível sai com 2', async () => {
  assert.equal(await run(join(tmpdir(), 'nao-existe-asyncapi.yaml'), quiet), 2);
});
