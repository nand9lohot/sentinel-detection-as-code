#!/usr/bin/env node
// Offline KQL analysis. Reads {tables, items} JSON on stdin and writes one result per
// item: parser and schema errors, plus the columns the query returns.
'use strict';
const fs = require('fs');
const path = require('path');

const pkg = path.dirname(require.resolve('@kusto/language-service-next/package.json'));
require(path.join(pkg, 'bridge.min.js'));
require(path.join(pkg, 'Kusto.Language.Bridge.min.js'));
const K = global.Kusto.Language;
const S = K.Symbols;
const T = S.ScalarTypes;

const TYPES = {
  string: T.String, datetime: T.DateTime, dynamic: T.Dynamic, long: T.Long, int: T.Int,
  real: T.Real, bool: T.Bool, guid: T.Guid, timespan: T.TimeSpan, decimal: T.Decimal,
};

// _GetWatchlist is built into Log Analytics but unknown to the language library.
const PRELUDE = 'let _GetWatchlist = (WatchlistAlias:string) { datatable(SearchKey:string)[] };\n';

function buildGlobals(tables) {
  const symbols = Object.entries(tables).map(([name, cols]) => {
    const columns = Object.entries(cols).map(([col, type]) => {
      if (!TYPES[type]) throw new Error(`Unknown type '${type}' for ${name}.${col}`);
      return new S.ColumnSymbol(col, TYPES[type]);
    });
    return new S.TableSymbol.$ctor4(name, columns);
  });
  return K.GlobalState.Default.WithDatabase(new S.DatabaseSymbol.$ctor1('workspace', symbols));
}

function analyze(query, globals) {
  const prefixed = !/\blet\s+_GetWatchlist\b/.test(query) && query.includes('_GetWatchlist');
  const text = prefixed ? PRELUDE + query : query;
  const offset = prefixed ? PRELUDE.length : 0;
  const code = K.KustoCode.ParseAndAnalyze(text, globals);

  const errors = [];
  const diagnostics = code.GetDiagnostics();
  for (let i = 0; i < diagnostics.Count; i++) {
    const d = diagnostics.getItem(i);
    if (d.Severity !== 'Error') continue;
    const line = query.slice(0, Math.max(0, d.Start - offset)).split('\n').length;
    errors.push({ code: d.Code, message: d.Message, line });
  }

  const columns = [];
  const result = code.ResultType;
  if (result && result.Columns) {
    for (let i = 0; i < result.Columns.Count; i++) columns.push(result.Columns.getItem(i).Name);
  }
  return { errors, columns };
}

const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const globals = buildGlobals(input.tables);
const output = input.items.map((item) => ({ id: item.id, ...analyze(item.query, globals) }));
process.stdout.write(JSON.stringify(output));
