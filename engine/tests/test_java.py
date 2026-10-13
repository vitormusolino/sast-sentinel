import pytest
from sast_engine.parsers.java_parser import JAVA_AVAILABLE, analyze_java

pytestmark = pytest.mark.skipif(not JAVA_AVAILABLE, reason="tree-sitter-java nao instalado")


def ids(code: str) -> list[tuple[str, int]]:
    findings, _ = analyze_java("A.java", code)
    return [(f.rule_id, f.line) for f in findings]


def wrap(body: str, params: str = "HttpServletRequest req, HttpServletResponse resp") -> str:
    return f"class A {{\n  void m({params}) throws Exception {{\n{body}\n  }}\n}}\n"


def test_servlet_taint_sqli_with_trace():
    code = wrap('    String id = req.getParameter("id");\n'
                '    st.executeQuery("SELECT * FROM u WHERE id = " + id);')
    findings, _ = analyze_java("A.java", code)
    taint = [f for f in findings if f.rule_id == "TAINT-SQLI"]
    assert taint and taint[0].line == 4
    assert "getParameter" in taint[0].trace[0].description and "Sink" in taint[0].trace[-1].description


def test_spring_annotation_is_source():
    code = wrap('    Runtime.getRuntime().exec("ping " + host);', params="@RequestParam String host")
    assert ("TAINT-CMDI", 3) in ids(code)


def test_sanitizers_and_reassignment():
    code = wrap('    int n = Integer.parseInt(req.getParameter("n"));\n'
                '    st.executeQuery("SELECT * FROM u WHERE id = " + n);\n'
                '    String name = req.getParameter("name");\n'
                '    name = "fixo";\n'
                '    resp.getWriter().println(name);\n'
                '    resp.getWriter().println(HtmlUtils.htmlEscape(req.getParameter("q")));')
    assert ids(code) == []


def test_order_matters_sink_before_cleanup():
    code = wrap('    String name = req.getParameter("name");\n'
                '    resp.sendRedirect(name);\n'
                '    name = "/";')
    assert ("TAINT-REDIRECT", 4) in ids(code)


def test_pattern_rules():
    code = """class A {
  private String apiKey = "a8f5f167f44f4964e6c998dee827110c";
  void m() throws Exception {
    MessageDigest.getInstance("SHA-1");
    MessageDigest.getInstance("SHA-256");
    Cipher.getInstance("AES");
    Cipher.getInstance("AES/GCM/NoPadding");
    new ObjectInputStream(in);
    DocumentBuilderFactory.newInstance();
  }
  public void checkServerTrusted(X509Certificate[] c, String a) {}
}
"""
    found = ids(code)
    assert ("JV003", 2) in found
    assert ("JV004", 4) in found and all(ln != 5 for _, ln in found)
    assert ("JV005", 6) in found and all(ln != 7 for _, ln in found)
    assert ("JV006", 8) in found and ("JV007", 9) in found
    assert ("JV009", 11) in found


def test_xxe_hardened_file_is_not_flagged():
    code = ('class A { void m() throws Exception {\n'
            '  DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n'
            '  f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n} }')
    assert ids(code) == []


def test_numeric_concatenation_is_not_sqli():
    code = wrap('    long id = 10;\n    st.executeQuery("SELECT * FROM u WHERE id = " + id);', params="")
    assert ids(code) == []
