"""Offline regression tests. No Azure calls and no claim of KQL engine validation."""

import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import kql_fp_patterns as patterns
import kql_lint as lint
import kql_test_harness as harness
from kql_text import rewrite_time_calls, segments, time_calls, views


def fixture():
    return {
        'name': 'late_arrival',
        'query_now': '2026-07-21T12:00:00Z',
        'tables': {'Events': {
            'schema': {'Timestamp': 'datetime', 'Message': 'string', '__ingestion_time': 'datetime'},
            'events': [{'Timestamp': '2026-07-21T10:00:00Z', 'Message': 'now() ago(1h)',
                        '__ingestion_time': '2026-07-21T11:59:00Z'}]}},
        'expected_alerts': 1,
        'expected_columns': {'Message': ['now() ago(1h)']}}


class LexicalTests(unittest.TestCase):
    def test_literals_and_comments_survive_byte_for_byte(self):
        queries = [
            'Events | where Message == "now()" | extend T=now() // ago(1h)\n',
            r'''Events | where Message == "escaped \" now() \\ ago(1h)" | extend T=now()''',
            '''Events | where Message == @'now() '' ago(1h)' | extend T=ago(1h)''',
            '''Events | where Message == h@"now() "" ago(1h)" | extend T=now(-1h)''',
            'Events | extend Message=```now()\nago(1h)\n“quoted”``` | extend T=now()',
            'Events /* now() \n ago(1h) */ | extend T=now()',
            'Events | where Message == "https://host/now()" // now()\n| extend T=now()',
        ]
        for query in queries:
            with self.subTest(query=query):
                original = [query[a:b] for kind, a, b in segments(query) if kind != 'code']
                rewritten = rewrite_time_calls(query)
                retained = [rewritten[a:b] for kind, a, b in segments(rewritten) if kind != 'code']
                self.assertEqual(original, retained)
                self.assertEqual(time_calls(rewritten), set())

    def test_offset_direction_and_nested_parentheses(self):
        self.assertEqual(rewrite_time_calls('print a=now(1h), b=now(-1h), c=ago((1h + 2m))'),
                         'print a=(__fixture_now + (1h)), b=(__fixture_now + (-1h)), c=(__fixture_now - ((1h + 2m)))')

    def test_offsets_inside_startofday_and_user_function(self):
        self.assertEqual(rewrite_time_calls('print T=startofday(ago(window)), N=my_now()'),
                         'print T=startofday((__fixture_now - (window))), N=my_now()')

    def test_views_preserve_offsets_and_newlines(self):
        query = 'T | extend S=```a\nb``` // “x”\n| count'
        for view in views(query):
            self.assertEqual(len(view), len(query))
            self.assertEqual([i for i,c in enumerate(view) if c=='\n'], [i for i,c in enumerate(query) if c=='\n'])

    def test_unterminated_and_invalid_calls_fail(self):
        for query in ['print x="now()', 'print x=```now()', 'T /* now()', 'print x=ago((1h)', 'print x=ago()', 'print x=ingestion_time(1h)']:
            with self.subTest(query=query), self.assertRaises(ValueError):
                rewrite_time_calls(query)


class HarnessTests(unittest.TestCase):
    def test_late_arrival_uses_fixture_ingestion_not_event_time(self):
        result = harness.build_test_query('Events | where ingestion_time() > ago(5m)', fixture())
        self.assertIn('where (__ingestion_time) > (__fixture_now - (5m))', result)
        self.assertIn('datetime(2026-07-21T10:00:00Z)', result)
        self.assertIn('datetime(2026-07-21T11:59:00Z)', result)
        self.assertEqual(time_calls(result), set())

    def test_clock_required_for_ago_even_without_now(self):
        f = fixture()
        del f['query_now']
        with self.assertRaisesRegex(ValueError, 'query_now'):
            harness.build_test_query('Events | where Timestamp > ago(1h)', f)

    def test_clock_not_required_for_literals_or_comments(self):
        f = fixture()
        del f['query_now']
        result = harness.build_test_query('Events | where Message == "now()" // ago(1h)', f)
        self.assertNotIn('let __fixture_now', result)
        self.assertIn('Message == "now()" // ago(1h)', result)

    def test_mock_ingestion_missing_column_rejected(self):
        f = fixture()
        del f['tables']['Events']['schema']['__ingestion_time']
        del f['tables']['Events']['events'][0]['__ingestion_time']
        with self.assertRaisesRegex(ValueError, '__ingestion_time'):
            harness.build_test_query('Events | extend I=ingestion_time()', f)

    def test_mock_ingestion_missing_row_value_rejected(self):
        f = fixture()
        f['tables']['Events']['events'][0]['__ingestion_time'] = None
        with self.assertRaisesRegex(ValueError, 'every row'):
            harness.build_test_query('Events | extend I=ingestion_time()', f)

    def test_empty_input_with_explicit_schema_emits(self):
        f = fixture()
        f['tables']['Events']['events'] = []
        f['expected_alerts'] = 0
        result = harness.build_test_query('Events | where ingestion_time() > ago(5m)', f)
        self.assertIn('__ingestion_time:datetime', result)
        self.assertIn('[\n\n]', result)

    def test_inferred_type_ignores_first_null_and_promotes_numbers(self):
        table = {'events': [{'Value': None, 'Count': 1}, {'Value': 3, 'Count': 2.5}]}
        self.assertEqual(harness.build_schema(table, 'Events'), {'Value':'long', 'Count':'real'})

    def test_all_null_needs_explicit_type(self):
        with self.assertRaisesRegex(ValueError, 'all-null'):
            harness.build_schema({'events': [{'Value': None}]}, 'Events')

    def test_mixed_schema_requires_explicit_type(self):
        with self.assertRaisesRegex(ValueError, 'mixed types'):
            harness.build_schema({'events': [{'Value': 3}, {'Value': '3'}]}, 'Events')

    def test_string_roundtrip_and_no_literal_newline(self):
        value = 'line1\nline2\r\t"quoted"\\path\x00 café'
        rendered = harness.render_value(value, 'string')
        self.assertEqual(json.loads(rendered), value)
        self.assertNotIn('\n', rendered)
        self.assertNotIn('\r', rendered)

    def test_timespan_and_boolean_values_are_typed(self):
        self.assertEqual(harness.render_value('5m', 'timespan'), 'timespan(5m)')
        self.assertEqual(harness.render_value(False, 'bool'), 'false')
        with self.assertRaises(ValueError):
            harness.render_value('false', 'bool')

    def test_invalid_typed_values_rejected(self):
        for value, kind in [('0); T | count //', 'long'), ('x); T', 'datetime'),
                            (float('nan'), 'real'), ('1h);T', 'timespan'), (2**31, 'int')]:
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                harness.render_value(value, kind)

    def test_timezone_normalized(self):
        self.assertEqual(harness.datetime_literal('2026-07-21T15:00:00+03:00'), 'datetime(2026-07-21T12:00:00Z)')

    def test_kusto_100_nanosecond_precision_preserved(self):
        self.assertEqual(harness.datetime_literal('2026-07-21T15:00:00.1234567+03:00'),
                         'datetime(2026-07-21T12:00:00.1234567Z)')
        with self.assertRaises(ValueError):
            harness.datetime_literal('2026-07-21T12:00:00.12345678Z')

    def test_invalid_identifier_and_reserved_names_rejected(self):
        with self.assertRaises(ValueError):
            harness.build_schema({'schema': {'X);T': 'string'}}, 'Events')
        with self.assertRaisesRegex(ValueError, 'reserved'):
            harness.build_test_query('let __fixture_now=now(); Events', fixture())

    def test_assertion_detects_count_and_missing_columns(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(harness.assert_results([], fixture(), 'missing_tp'))
            self.assertFalse(harness.assert_results([{'Other':1}], fixture(), 'missing_column'))
            self.assertTrue(harness.assert_results([{'Message':'now() ago(1h)'}], fixture(), 'tp'))

    def test_missing_assertion_never_reports_pass(self):
        with self.assertRaisesRegex(ValueError, 'expected_alerts'):
            harness.assert_results([], {}, 'no_assertion')

    def test_malformed_column_assertion_fails_validation(self):
        for value in [[], None, {'Message':'not-a-list'}]:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'expected_columns'):
                harness.validate_assertions({'expected_alerts':0, 'expected_columns':value})

    def test_cli_emit_is_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)
            (p/'rule.kql').write_text('Events | where ingestion_time() > ago(5m)')
            (p/'fixture.json').write_text(json.dumps(fixture()))
            args=['harness','--query',str(p/'rule.kql'),'--fixture',str(p/'fixture.json'),'--out-dir',str(p/'out')]
            with patch.object(sys,'argv',args), patch.object(harness,'run_query') as run, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(harness.main(),0)
                run.assert_not_called()
            self.assertTrue((p/'out/late_arrival.test.kql').is_file())

    def test_cli_refuses_path_name_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp); f=fixture(); f['name']='../escape'
            (p/'rule.kql').write_text('Events')
            (p/'fixture.json').write_text(json.dumps(f))
            args=['harness','--query',str(p/'rule.kql'),'--fixture',str(p/'fixture.json'),'--out-dir',str(p/'out')]
            with patch.object(sys,'argv',args), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(harness.main(),2)
            self.assertFalse((p/'out').exists())

    def test_cli_run_requires_assertion_before_azure(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp); f=fixture(); del f['expected_alerts']
            (p/'rule.kql').write_text('Events')
            (p/'fixture.json').write_text(json.dumps(f))
            args=['harness','--query',str(p/'rule.kql'),'--fixture',str(p/'fixture.json'),'--run','--workspace','test']
            with patch.object(sys,'argv',args), patch.object(harness,'run_query') as run, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(harness.main(),2)
                run.assert_not_called()


class LintTests(unittest.TestCase):
    def codes(self, query):
        return {f[1] for f in lint.lint_query(query,'sentinel',True)[0]}

    def test_curly_quotes_in_comments_and_strings_are_data(self):
        queries=['T // “quoted”', 'T | where Message == "“quoted”"',
                 'T | extend S=```“x”\njoin X on Key```', 'T /* “x”\njoin X on Key */']
        for q in queries:
            with self.subTest(query=q):
                self.assertNotIn('E017',self.codes(q))
                self.assertNotIn('E001',self.codes(q))

    def test_curly_delimiters_still_error(self):
        self.assertIn('E017',self.codes('T | where Message == “x”'))

    def test_three_character_index_boundary(self):
        self.assertNotIn('W006',self.codes('T | where Message has "sql"'))
        self.assertIn('W006',self.codes('T | where Message has "ab"'))

    def test_valid_min_and_sec_aliases(self):
        for unit in ['m','min','s','sec']:
            self.assertNotIn('E017',self.codes(f'T | where TimeGenerated > ago(5{unit})'))
        self.assertIn('E017',self.codes('T | where TimeGenerated > ago(1hr)'))

    def test_literal_text_cannot_suppress_real_finding(self):
        self.assertIn('E001',self.codes('T | join U on X | extend Note="lint:ignore E001"'))
        self.assertNotIn('E001',self.codes('T | join U on X // lint:ignore E001'))

    def test_url_does_not_hide_rest_of_line(self):
        self.assertIn('E001',self.codes('T | where Url == "https://host/path" | join U on X'))

    def test_escaped_quotes_do_not_create_fake_operators(self):
        self.assertNotIn('E001',self.codes(r'''T | extend Message="\" join U on X"'''))

    def test_numeric_column_string_warning_is_reachable(self):
        self.assertIn('W025',self.codes('T | where EventID == "4688"'))
        self.assertNotIn('W025',self.codes('T | where EventID == 4688'))

    def test_bundled_selftest_still_passes(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(lint.selftest(),0)


class PatternTests(unittest.TestCase):
    def test_watchlist_cannot_be_generated_without_scope(self):
        for name in ['watchlist_exclude','scoped_watchlist_exclusion','env_filter_fence']:
            params={p:'X' for p in patterns.PATTERNS[name]['params'] if p!='rule_scope'}
            with self.subTest(name=name), self.assertRaisesRegex(ValueError,'rule_scope'):
                patterns.generate_pattern(name,params)

    def test_null_helper_does_not_add_identity_exclusions(self):
        q=patterns.generate_pattern('null_safe',{'field':'AccountName'})
        self.assertEqual(q.strip(),'| where isnotempty(AccountName)')

    def test_templates_render_and_have_balanced_lexical_structure(self):
        for name, p in patterns.PATTERNS.items():
            with self.subTest(name=name):
                q=patterns.generate_pattern(name,{key:'X' for key in p['params']})
                self.assertTrue(q.strip())
                list(segments(q))


if __name__ == '__main__':
    unittest.main()
