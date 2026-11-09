#!/usr/bin/env node
// Valida os `examples` das mensagens application/json do asyncapi.yaml contra o `payload` da mensagem
// (JSON Schema 2020-12). O AsyncAPI CLI 6.x só confere exemplos de documentos 2.x; este passo cobre o 3.x
// (spec 017 RF-08, task 044).
//
//   node scripts/asyncapi-examples/check.mjs eventbus/nats/asyncapi.yaml
//
// Saída: uma linha por falha (mensagem, exemplo e erros do ajv) e um aviso por mensagem JSON sem exemplo.
// Código de saída: 0 sem falhas, 1 com falhas, 2 quando o documento não pôde ser lido ou derreferenciado.
import $RefParser from '@apidevtools/json-schema-ref-parser';
import Ajv2020 from 'ajv/dist/2020.js';
import { pathToFileURL } from 'node:url';

const JSON_CT = 'application/json';

// Lê o documento e resolve todas as refs, inclusive as externas (openapi e golden JSON dos testdata).
export async function loadDocument(file) {
  return $RefParser.dereference(file);
}

// Content type efetivo: o da mensagem, senão o do último trait que define um, senão o padrão do documento.
function contentTypeOf(msg, doc) {
  if (msg.contentType) return msg.contentType;
  const traits = msg.traits || [];
  for (let i = traits.length - 1; i >= 0; i--) {
    if (traits[i] && traits[i].contentType) return traits[i].contentType;
  }
  return doc.defaultContentType;
}

// Mensagens do documento: as de components.messages e as definidas direto nos canais (sem repetir objetos).
function collectMessages(doc) {
  const out = [];
  const seen = new Set();
  const add = (id, msg) => {
    if (!msg || typeof msg !== 'object' || seen.has(msg)) return;
    seen.add(msg);
    out.push([id, msg]);
  };
  for (const [id, msg] of Object.entries((doc.components && doc.components.messages) || {})) add(id, msg);
  for (const [ch, channel] of Object.entries(doc.channels || {})) {
    for (const [id, msg] of Object.entries((channel && channel.messages) || {})) add(`${ch}/${id}`, msg);
  }
  return out;
}

// Confere os exemplos de um documento já derreferenciado. Não escreve nada; devolve o relatório.
export function checkExamples(doc) {
  const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: false });
  const report = { examples: 0, failures: [], warnings: [] };
  for (const [id, msg] of collectMessages(doc)) {
    if (contentTypeOf(msg, doc) !== JSON_CT) continue;
    // exemplos da mensagem e dos traits aplicados a ela
    const examples = [...(msg.examples || []), ...(msg.traits || []).flatMap((t) => (t && t.examples) || [])];
    if (examples.length === 0) {
      report.warnings.push(`${id}: mensagem JSON sem exemplo`);
      continue;
    }
    if (!msg.payload) {
      report.failures.push({ message: id, example: '-', errors: 'mensagem com exemplos e sem payload' });
      continue;
    }
    let validate;
    try {
      validate = ajv.compile(msg.payload);
    } catch (err) {
      report.failures.push({ message: id, example: '-', errors: `payload não compila: ${err.message}` });
      continue;
    }
    examples.forEach((ex, i) => {
      report.examples++;
      const name = (ex && ex.name) || `#${i}`;
      if (!ex || !('payload' in ex)) {
        report.failures.push({ message: id, example: name, errors: 'exemplo sem payload' });
        return;
      }
      if (!validate(ex.payload)) {
        report.failures.push({ message: id, example: name, errors: ajv.errorsText(validate.errors, { separator: '; ' }) });
      }
    });
  }
  return report;
}

// Executa sobre um arquivo e imprime o relatório; devolve o código de saída.
export async function run(file, log = console.log) {
  let doc;
  try {
    doc = await loadDocument(file);
  } catch (err) {
    log(`ERRO ${file}: ${err.message}`);
    return 2;
  }
  const r = checkExamples(doc);
  for (const w of r.warnings) log(`AVISO ${w}`);
  for (const f of r.failures) log(`FALHA ${f.message}/${f.example}: ${f.errors}`);
  log(`asyncapi examples: ${r.examples} exemplos, ${r.failures.length} falhas, ${r.warnings.length} avisos`);
  return r.failures.length ? 1 : 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  const file = process.argv[2];
  if (!file) {
    console.error('uso: check.mjs <asyncapi.yaml>');
    process.exit(2);
  }
  process.exit(await run(file));
}
