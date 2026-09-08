import json
import os
import tempfile
import unittest

from neural_schema import (
    K_CLASS,
    K_FUNCTION,
    K_IMPORT,
    K_METHOD,
    K_MODULE,
    K_PROJECT,
    K_VULN,
    R_CALLS,
    R_CONTAINS,
    R_INHERITS,
    PythonAnalyzer,
    SchemaGraph,
    analyze_directory,
    analyze_file,
    build_report,
    compute_layout,
    export_html,
    export_json,
    export_report,
    main,
    report_to_text,
)


class TestSchemaGraph(unittest.TestCase):
    def test_schema_graph_nodes_and_edges(self):
        sg = SchemaGraph(title="TestArchitecture", kind="code", language="python")
        sg.add_node("mod:sample", K_MODULE, "sample.py", lines=50)
        sg.add_node("fn:worker", K_FUNCTION, "worker", complexity=3)
        sg.add_edge("mod:sample", "fn:worker", R_CONTAINS)

        self.assertTrue(sg.has_node("mod:sample"))
        self.assertTrue(sg.has_node("fn:worker"))
        self.assertFalse(sg.has_node("unknown"))

        nodes = sg.nodes()
        self.assertEqual(len(nodes), 2)
        self.assertEqual(nodes["mod:sample"]["kind"], K_MODULE)

        edges = sg.edges()
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0], ("mod:sample", "fn:worker", R_CONTAINS))

        nbrs = sg.neighbors("mod:sample")
        self.assertIn("fn:worker", nbrs)

        deg = sg.degree()
        self.assertEqual(deg["mod:sample"], 1)
        self.assertEqual(deg["fn:worker"], 1)

        counts = sg.counts()
        self.assertEqual(counts[K_MODULE], 1)
        self.assertEqual(counts[K_FUNCTION], 1)

        data = sg.to_dict()
        self.assertEqual(data["meta"]["title"], "TestArchitecture")
        self.assertEqual(data["meta"]["node_count"], 2)
        self.assertEqual(data["meta"]["edge_count"], 1)


class TestPythonAnalyzer(unittest.TestCase):
    def setUp(self):
        self.sample_code = '''
import os
import sys

class BaseService:
    def execute(self):
        return True

class DataService(BaseService):
    def process(self, value):
        if value > 0:
            os.system("echo Processing")
        return value * 2

def helper_function():
    service = DataService()
    return service.process(10)

def dead_function():
    return 42
'''
        self.temp_dir = tempfile.TemporaryDirectory()
        self.sample_file = os.path.join(self.temp_dir.name, "service.py")
        with open(self.sample_file, "w", encoding="utf-8") as f:
            f.write(self.sample_code)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_ast_analysis_elements(self):
        sg = analyze_file(self.sample_file, include_external=True, sast=True)
        nodes = sg.nodes()
        labels = {attrs["label"]: attrs["kind"] for attrs in nodes.values()}

        self.assertIn("os", labels)
        self.assertEqual(labels["os"], K_IMPORT)
        self.assertIn("BaseService", labels)
        self.assertEqual(labels["BaseService"], K_CLASS)
        self.assertIn("DataService", labels)
        self.assertEqual(labels["DataService"], K_CLASS)
        self.assertIn("process", labels)
        self.assertEqual(labels["process"], K_METHOD)
        self.assertIn("helper_function", labels)
        self.assertEqual(labels["helper_function"], K_FUNCTION)

        # Check inheritance relation BaseService <- DataService
        edges = sg.edges()
        has_inheritance = any(r == R_INHERITS for s, d, r in edges)
        self.assertTrue(has_inheritance)

        # Check SAST tagging for os.system
        vuln_nodes = [attrs for attrs in nodes.values() if attrs["kind"] == K_VULN]
        self.assertTrue(any("os.system" in v["label"] for v in vuln_nodes))

    def test_build_report(self):
        sg = analyze_file(self.sample_file, include_external=False, sast=True)
        rep = build_report(sg)
        self.assertEqual(rep["title"], "service.py")
        self.assertGreaterEqual(rep["n_functions"], 4)
        self.assertGreaterEqual(rep["avg_complexity"], 1.0)

        # Verify dead_code detection includes dead_function
        dead_labels = [f["label"] for f in rep["dead_code"]]
        self.assertIn("dead_function", dead_labels)

        # Verify text conversion
        rep_text = report_to_text(rep)
        self.assertIn("STATIC ANALYSIS REPORT", rep_text)
        self.assertIn("dead_function", rep_text)

    def test_analyze_directory(self):
        sg = analyze_directory(self.temp_dir.name, include_external=True, sast=True)
        nodes = sg.nodes()
        kinds = {attrs["kind"] for attrs in nodes.values()}
        self.assertIn(K_PROJECT, kinds)
        self.assertIn(K_MODULE, kinds)
        self.assertIn(K_FUNCTION, kinds)



class TestLayoutAndExports(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.sg = SchemaGraph(title="ExportTest", kind="code", language="python")
        self.sg.add_node("n1", K_MODULE, "app.py")
        self.sg.add_node("n2", K_FUNCTION, "run")
        self.sg.add_edge("n1", "n2", R_CONTAINS)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_compute_layout_fallback(self):
        pos = compute_layout(self.sg, algo="spring")
        self.assertIn("n1", pos)
        self.assertIn("n2", pos)
        self.assertEqual(len(pos["n1"]), 2)

    def test_export_json(self):
        json_path = os.path.join(self.temp_dir.name, "export.json")
        export_json(self.sg, json_path)
        self.assertTrue(os.path.exists(json_path))

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["meta"]["title"], "ExportTest")
        self.assertEqual(len(data["nodes"]), 2)

    def test_export_report(self):
        md_path = os.path.join(self.temp_dir.name, "export.md")
        export_report(self.sg, md_path)
        self.assertTrue(os.path.exists(md_path))
        with open(md_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("Static Analysis Report", content)

    def test_export_html(self):
        html_path = os.path.join(self.temp_dir.name, "export.html")
        export_html(self.sg, html_path)
        self.assertTrue(os.path.exists(html_path))
        with open(html_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("NeuralSchema", content)


class TestCLIIntegration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.src_file = os.path.join(self.temp_dir.name, "cli_sample.py")
        with open(self.src_file, "w", encoding="utf-8") as f:
            f.write("def calculate(x): return x * 2\n")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_cli_headless_run(self):
        out_base = os.path.join(self.temp_dir.name, "out_schema")
        ret = main([
            "--file", self.src_file,
            "--export", "json", "report", "html",
            "--out", out_base,
            "--no-gui"
        ])
        self.assertEqual(ret, 0)
        self.assertTrue(os.path.exists(f"{out_base}.json"))
        self.assertTrue(os.path.exists(f"{out_base}.md"))
        self.assertTrue(os.path.exists(f"{out_base}.html"))


if __name__ == "__main__":
    unittest.main()
