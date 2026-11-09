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
  const { file, cleanup } = tempCopy((t) => {
    const out = t.replace('ok: true\n', 'ok: "yes"\n');
    assert.ok(out !== t, 'exemplo ACMEReply "ok: true" não encontrado no asyncapi');
    return out;
  });
  try {
    const lines = [];
    assert.equal(await run(file, (l) => lines.push(l)), 1);
    assert.ok(lines.some((l) => l.startsWith('FALHA ACMEReply/ok:')), lines.join('\n'));
  } finally {
    cleanup();
  }
});

test('cópia do asyncapi com golden externo inválido falha', async () => {
  // Troca a ref de um golden por uma cópia temporária com flow.src_port de tipo errado.
  const golden = join(ROOT, 'internal/web/testdata/events/tls.client_hello.json');
  const bad = JSON.parse(readFileSync(golden, 'utf8'));
  bad.flow.src_port = 'not-a-port';
  const dir = mkdtempSync(join(tmpdir(), 'fs-golden-'));
  const badFile = join(dir, 'bad.json');
  writeFileSync(badFile, JSON.stringify(bad));
  const { file, cleanup } = tempCopy((t) => {
    const out = t.replace(`${ROOT}/internal/web/testdata/events/tls.client_hello.json`, badFile);
    assert.ok(out !== t, 'ref do golden tls.client_hello.json não encontrada no asyncapi');
    return out;
  });
  try {
    const r = checkExamples(await loadDocument(file));
    const hit = r.failures.filter((f) => f.message === 'TLSClientHello' && /src_port/.test(f.errors));
    assert.equal(hit.length, 1, JSON.stringify(r.failures));
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
