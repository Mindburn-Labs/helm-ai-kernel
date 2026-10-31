from pathlib import Path
import unittest

from deadcode_profiles import Profile, combined_findings, read_profile


class ProfileTests(unittest.TestCase):
    def test_same_declaration_live_in_either_target_is_reachable(self):
        source = Path('/module/shared.go')
        native = Profile({('p wasm_live', source), ('p neither', source)}, {source})
        wasm = Profile({('p native_live', source), ('p neither', source)}, {source})
        self.assertEqual(combined_findings([native, wasm]), ['p neither'])

    def test_uncompiled_source_does_not_hide_a_finding(self):
        native_source, wasm_source = Path('/module/native.go'), Path('/module/js.go')
        native = Profile({('p native_only', native_source)}, {native_source})
        wasm = Profile({('p wasm_only', wasm_source)}, {wasm_source})
        self.assertEqual(combined_findings([native, wasm]), ['p native_only', 'p wasm_only'])

    def test_same_name_in_different_target_files_remains_separate(self):
        native_source, wasm_source = Path('/module/native.go'), Path('/module/js.go')
        native = Profile({('p implementation', native_source)}, {native_source})
        wasm = Profile(set(), {wasm_source})
        self.assertEqual(combined_findings([native, wasm]), ['p implementation'])

    def test_tool_output_is_bound_to_selected_source(self):
        root = Path('/module')
        report = [{'Path': 'p', 'Funcs': [{'Name': 'f', 'Position': {'File': 'shared.go'}}]}]
        profile = read_profile(report, '/module/shared.go\n', root)
        self.assertEqual(profile.dead, {('p f', root / 'shared.go')})
        for files in ['', 'shared.go\n', '/module/other.go\n']:
            with self.subTest(files=files), self.assertRaises(ValueError):
                read_profile(report, files, root)
        self.assertEqual(read_profile(None, '/module/shared.go\n', root).dead, set())
        with self.assertRaises(ValueError):
            combined_findings([])


if __name__ == '__main__':
    unittest.main()
