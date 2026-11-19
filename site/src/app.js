// In-browser demo. The scanner is the same Python package that runs on the command line,
// executed by Pyodide. Nothing typed into the page is sent anywhere: the page's Content
// Security Policy allows connections to this site only.

const ui = JSON.parse(document.getElementById("ui").textContent);
const input = document.getElementById("input");
const status = document.getElementById("status");
const results = document.getElementById("results");
const runButton = document.getElementById("run");
let scanner = null;

function example(id) {
  input.value = JSON.parse(document.getElementById(id).textContent).trim();
  results.replaceChildren();
  setStatus("");
}
document.getElementById("example-config").addEventListener("click", () => example("ex-config"));
document.getElementById("example-tools").addEventListener("click", () => example("ex-tools"));

function setStatus(text, isError = false) {
  status.textContent = text;
  status.className = isError ? "error" : "";
}

async function loadScanner() {
  // Absolute URLs: a dynamic import treats "pyodide/..." as a package name, not a path.
  const root = new URL(ui.base, document.baseURI);
  const { loadPyodide } = await import(new URL("pyodide/pyodide.mjs", root).href);
  const pyodide = await loadPyodide({ indexURL: new URL("pyodide/", root).href });
  await pyodide.loadPackage(["pydantic"]);
  const wheel = await fetch(new URL("pkg/" + ui.wheel, root));
  if (!wheel.ok) throw new Error("could not load " + ui.wheel);
  pyodide.unpackArchive(await wheel.arrayBuffer(), "wheel");
  pyodide.runPython(
    "from foretaster.paste import scan_pasted\n" +
    "def scan_json(text):\n" +
    "    return scan_pasted(text).model_dump_json()\n"
  );
  return pyodide.globals.get("scan_json");
}

// Everything below writes scan output with textContent only. Findings quote text
// taken from the pasted file, which must be treated as hostile.
function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function renderFinding(finding) {
  const card = element("article", "finding " + finding.severity);
  const title = element("h3");
  title.append(
    element("span", "badge " + finding.severity, finding.severity),
    element("span", "rule", finding.rule_id),
    document.createTextNode(finding.title)
  );
  const where = [];
  if (finding.location.line) where.push(ui.line + " " + finding.location.line);
  if (finding.server) where.push(ui.server + " " + finding.server);
  if (finding.tool) where.push(ui.tool + " " + finding.tool);
  card.append(title);
  if (where.length) card.append(element("p", "where", where.join(" · ")));
  card.append(element("p", "", finding.message));
  if (finding.evidence) card.append(element("pre", "", finding.evidence));
  card.append(element("p", "", ui.fix + " " + finding.remediation));
  if (finding.references.length) card.append(element("p", "refs", finding.references.join(" · ")));
  return card;
}

function render(report) {
  const nodes = [];
  for (const error of report.errors) {
    nodes.push(element("p", "summary", ui.unreadable + " " + error.message));
  }
  if (!report.errors.length) {
    const counts = Object.entries(report.summary.findings)
      .filter(([, count]) => count > 0)
      .map(([severity, count]) => count + " " + severity);
    const scanned = ui.scanned
      .replace("{servers}", report.summary.servers)
      .replace("{tools}", report.summary.tools);
    nodes.push(element("p", "summary", scanned + " " + (counts.length ? counts.join(", ") + "." : ui.clean)));
  }
  for (const finding of report.findings) nodes.push(renderFinding(finding));
  results.replaceChildren(...nodes);
}

runButton.addEventListener("click", async () => {
  if (!input.value.trim()) {
    setStatus(ui.empty, true);
    return;
  }
  runButton.disabled = true;
  try {
    if (!scanner) {
      setStatus(ui.loading);
      scanner = await loadScanner();
    }
    setStatus(ui.scanning);
    render(JSON.parse(scanner(input.value)));
    setStatus(ui.done);
  } catch (error) {
    setStatus(ui.failed + " " + error, true);
  } finally {
    runButton.disabled = false;
  }
});
