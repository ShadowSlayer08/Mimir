// redengine_viewer — read-only desktop viewer for the redengine engagement JSON.
//
// AUTHORIZED / LAB / CTF USE ONLY. This app DISPLAYS an engagement and COPIES
// staged operator commands to the clipboard. It NEVER runs scans or exploits;
// the Python engine does the scope-gated detection scanning and a human operator
// runs the staged commands in their own tooling. There is intentionally no
// process-execution code path anywhere in this app.
//
// Input: a JSON file produced by `redengine-cli <args> --emit-json <file>`
// (assess.py build_engagement_json), or any previously exported engagement JSON.

import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:file_picker/file_picker.dart';

void main() => runApp(const RedEngineViewerApp());

class RedEngineViewerApp extends StatelessWidget {
  const RedEngineViewerApp({super.key});

  @override
  Widget build(BuildContext context) {
    final base = ThemeData.dark(useMaterial3: true);
    return MaterialApp(
      title: 'redengine viewer',
      debugShowCheckedModeBanner: false,
      theme: base.copyWith(
        scaffoldBackgroundColor: const Color(0xFF0E1116),
        cardTheme: const CardThemeData(
          color: Color(0xFF161B22),
          elevation: 0,
          margin: EdgeInsets.zero,
        ),
        colorScheme: base.colorScheme.copyWith(
          primary: const Color(0xFF4C8DFF),
          surface: const Color(0xFF161B22),
        ),
      ),
      home: const HomePage(),
    );
  }
}

// --------------------------------------------------------------------------- //
// Severity helpers (mirror the engine's palette)
// --------------------------------------------------------------------------- //
const Map<String, Color> kSevColor = {
  'critical': Color(0xFFE5484D),
  'high': Color(0xFFF76808),
  'medium': Color(0xFFFFB224),
  'low': Color(0xFF8B95A5),
  'info': Color(0xFF4C8DFF),
};
const List<String> kSevOrder = ['critical', 'high', 'medium', 'low', 'info'];

Color sevColor(String s) => kSevColor[s.toLowerCase()] ?? const Color(0xFF8B95A5);

Color gradeColor(String g) {
  switch (g.toUpperCase()) {
    case 'F':
    case 'D':
      return const Color(0xFFE5484D);
    case 'C':
      return const Color(0xFFFFB224);
    default:
      return const Color(0xFF7BD88F);
  }
}

// --------------------------------------------------------------------------- //
// Model — defensive parsing of the engagement JSON contract
// --------------------------------------------------------------------------- //
class Engagement {
  final Map<String, dynamic> meta;
  final List<Host> hosts;
  final List<Finding> findings;
  final List<AttackPath> attackPaths;
  final List<KillChainStage> killchain;

  Engagement({
    required this.meta,
    required this.hosts,
    required this.findings,
    required this.attackPaths,
    required this.killchain,
  });

  factory Engagement.fromJson(Map<String, dynamic> j) {
    List<T> list<T>(dynamic v, T Function(Map<String, dynamic>) f) =>
        (v is List ? v : const [])
            .whereType<Map<String, dynamic>>()
            .map(f)
            .toList();
    final kc = (j['killchain'] is Map<String, dynamic>)
        ? (j['killchain']['stages'])
        : null;
    return Engagement(
      meta: (j['meta'] is Map<String, dynamic>) ? j['meta'] as Map<String, dynamic> : {},
      hosts: list(j['hosts'], Host.fromJson),
      findings: list(j['findings'], Finding.fromJson),
      attackPaths: list(j['attack_paths'], AttackPath.fromJson),
      killchain: list(kc, KillChainStage.fromJson),
    );
  }

  Map<String, int> get severityCounts {
    final m = (meta['severity_counts'] is Map<String, dynamic>)
        ? meta['severity_counts'] as Map<String, dynamic>
        : const {};
    final out = <String, int>{};
    for (final s in kSevOrder) {
      out[s] = (m[s] is num) ? (m[s] as num).toInt() : 0;
    }
    if (out.values.every((v) => v == 0) && findings.isNotEmpty) {
      for (final f in findings) {
        out[f.severity] = (out[f.severity] ?? 0) + 1;
      }
    }
    return out;
  }
}

class Port {
  final int port;
  final String protocol;
  final String service;
  final String product;
  final String version;
  Port(this.port, this.protocol, this.service, this.product, this.version);
  factory Port.fromJson(Map<String, dynamic> j) => Port(
        (j['port'] is num) ? (j['port'] as num).toInt() : 0,
        (j['protocol'] ?? 'tcp').toString(),
        (j['service'] ?? '').toString(),
        (j['product'] ?? '').toString(),
        (j['version'] ?? '').toString(),
      );
  String get label {
    final desc = [service, product, version].where((s) => s.isNotEmpty).join(' ');
    return '$port/$protocol  $desc'.trimRight();
  }
}

class Host {
  final String ip;
  final String label;
  final String os;
  final String deviceClass;
  final String grade;
  final int openPorts;
  final int findingCount;
  final List<Port> ports;
  Host(this.ip, this.label, this.os, this.deviceClass, this.grade,
      this.openPorts, this.findingCount, this.ports);
  factory Host.fromJson(Map<String, dynamic> j) => Host(
        (j['ip'] ?? '').toString(),
        (j['label'] ?? j['host'] ?? '?').toString(),
        (j['os'] ?? '').toString(),
        (j['device_class'] ?? '').toString(),
        (j['grade'] ?? '?').toString(),
        (j['open_ports'] is num) ? (j['open_ports'] as num).toInt() : 0,
        (j['finding_count'] is num)
            ? (j['finding_count'] as num).toInt()
            : ((j['findings'] is num) ? (j['findings'] as num).toInt() : 0),
        (j['ports'] is List)
            ? (j['ports'] as List)
                .whereType<Map<String, dynamic>>()
                .map(Port.fromJson)
                .toList()
            : const [],
      );
}

class Finding {
  final String host;
  final int port;
  final String severity;
  final String category;
  final String title;
  final List<String> cve;
  Finding(this.host, this.port, this.severity, this.category, this.title, this.cve);
  factory Finding.fromJson(Map<String, dynamic> j) => Finding(
        (j['host'] ?? '?').toString(),
        (j['port'] is num) ? (j['port'] as num).toInt() : 0,
        (j['severity'] ?? 'info').toString().toLowerCase(),
        (j['category'] ?? '').toString(),
        (j['title'] ?? '').toString(),
        (j['cve'] is List)
            ? (j['cve'] as List).map((e) => e.toString()).toList()
            : const [],
      );
  String get target => port > 0 ? '$host:$port' : host;
}

class Abuse {
  final String impact;
  final String how;
  final String opsec;
  Abuse(this.impact, this.how, this.opsec);
  factory Abuse.fromJson(Map<String, dynamic> j) => Abuse(
        (j['impact'] ?? '').toString(),
        (j['how'] ?? '').toString(),
        (j['opsec'] ?? '').toString(),
      );
  bool get isEmpty => impact.isEmpty && how.isEmpty && opsec.isEmpty;
}

class Step {
  final int order;
  final String tactic;
  final String techniqueId;
  final String technique;
  final String host;
  final String guidance;
  final String command;
  final Abuse abuse;
  Step(this.order, this.tactic, this.techniqueId, this.technique, this.host,
      this.guidance, this.command, this.abuse);
  factory Step.fromJson(Map<String, dynamic> j) {
    final ab = (j['abuse'] is Map<String, dynamic>)
        ? Abuse.fromJson(j['abuse'] as Map<String, dynamic>)
        : Abuse('', '', '');
    final cmd = (j['command'] ?? '').toString();
    return Step(
      (j['order'] is num) ? (j['order'] as num).toInt() : 0,
      (j['tactic'] ?? '').toString(),
      (j['technique_id'] ?? '').toString(),
      (j['technique'] ?? j['title'] ?? '').toString(),
      (j['host'] ?? '').toString(),
      (j['guidance'] ?? '').toString(),
      // Fall back to abuse.how / guidance if the emitter omitted `command`,
      // mirroring pentest_console._exploit_command.
      cmd.isNotEmpty ? cmd : (ab.how.isNotEmpty ? ab.how : (j['guidance'] ?? '').toString()),
      ab,
    );
  }
}

class AttackPath {
  final String id;
  final String name;
  final String kind;
  final String severity;
  final String confidence;
  final int score;
  final List<String> hosts;
  final String rationale;
  final List<Step> steps;
  AttackPath(this.id, this.name, this.kind, this.severity, this.confidence,
      this.score, this.hosts, this.rationale, this.steps);
  factory AttackPath.fromJson(Map<String, dynamic> j) => AttackPath(
        (j['id'] ?? '').toString(),
        (j['name'] ?? '').toString(),
        (j['kind'] ?? '').toString(),
        (j['severity'] ?? 'info').toString().toLowerCase(),
        (j['confidence'] ?? '').toString(),
        (j['score'] is num) ? (j['score'] as num).toInt() : 0,
        (j['hosts'] is List)
            ? (j['hosts'] as List).map((e) => e.toString()).toList()
            : const [],
        (j['rationale'] ?? '').toString(),
        (j['steps'] is List)
            ? (j['steps'] as List)
                .whereType<Map<String, dynamic>>()
                .map(Step.fromJson)
                .toList()
            : const [],
      );
}

class KillChainStage {
  final int id;
  final String name;
  final String objective;
  final int stagedStepCount;
  final List<String> pathIds;
  KillChainStage(this.id, this.name, this.objective, this.stagedStepCount, this.pathIds);
  factory KillChainStage.fromJson(Map<String, dynamic> j) => KillChainStage(
        (j['id'] is num) ? (j['id'] as num).toInt() : 0,
        (j['name'] ?? '').toString(),
        (j['objective'] ?? '').toString(),
        (j['staged_step_count'] is num)
            ? (j['staged_step_count'] as num).toInt()
            : 0,
        (j['path_ids'] is List)
            ? (j['path_ids'] as List).map((e) => e.toString()).toList()
            : const [],
      );
}

// --------------------------------------------------------------------------- //
// Home page
// --------------------------------------------------------------------------- //
class HomePage extends StatefulWidget {
  const HomePage({super.key});
  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  Engagement? _eng;
  String? _sourcePath;
  String? _error;
  int _tab = 0;

  Future<void> _openFile() async {
    setState(() => _error = null);
    try {
      final res = await FilePicker.platform.pickFiles(
        dialogTitle: 'Open engagement JSON (redengine-cli --emit-json output)',
        type: FileType.custom,
        allowedExtensions: ['json'],
      );
      if (res == null || res.files.isEmpty) return;
      final path = res.files.single.path;
      if (path == null) {
        setState(() => _error = 'Could not read the selected file path.');
        return;
      }
      final text = await File(path).readAsString();
      final decoded = jsonDecode(text);
      if (decoded is! Map<String, dynamic>) {
        setState(() => _error = 'Not a redengine engagement object (expected a JSON object).');
        return;
      }
      setState(() {
        _eng = Engagement.fromJson(decoded);
        _sourcePath = path;
        _tab = 0;
      });
    } catch (e) {
      setState(() => _error = 'Failed to load engagement: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    final eng = _eng;
    return Scaffold(
      appBar: AppBar(
        backgroundColor: const Color(0xFF161B22),
        title: const Text('redengine viewer'),
        actions: [
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 8),
            child: FilledButton.icon(
              onPressed: _openFile,
              icon: const Icon(Icons.folder_open),
              label: const Text('Open engagement JSON'),
            ),
          ),
        ],
      ),
      body: Column(
        children: [
          const _BoundaryBanner(),
          if (_error != null)
            Container(
              width: double.infinity,
              color: const Color(0x33E5484D),
              padding: const EdgeInsets.all(10),
              child: Text(_error!, style: const TextStyle(color: Color(0xFFE5484D))),
            ),
          if (eng == null)
            const Expanded(child: _EmptyState())
          else
            Expanded(
              child: Column(
                children: [
                  _SourceBar(meta: eng.meta, path: _sourcePath),
                  _Tabs(
                    index: _tab,
                    onChanged: (i) => setState(() => _tab = i),
                    labels: const ['Dashboard', 'Attack paths'],
                  ),
                  Expanded(
                    child: _tab == 0
                        ? DashboardView(eng: eng)
                        : AttackPathsView(eng: eng),
                  ),
                ],
              ),
            ),
        ],
      ),
    );
  }
}

class _BoundaryBanner extends StatelessWidget {
  const _BoundaryBanner();
  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      color: const Color(0x22E5484D),
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      child: Row(
        children: const [
          Icon(Icons.shield_outlined, color: Color(0xFFE5484D), size: 18),
          SizedBox(width: 10),
          Expanded(
            child: Text(
              'STAGING ONLY — this app executes NOTHING. No scans, no exploits. '
              'It displays the engagement and copies staged commands for a human '
              'operator to run manually, in authorized scope, with their own tooling.',
              style: TextStyle(color: Color(0xFFE5484D), fontWeight: FontWeight.w600),
            ),
          ),
        ],
      ),
    );
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState();
  @override
  Widget build(BuildContext context) {
    return const Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.description_outlined, size: 56, color: Color(0xFF8B95A5)),
          SizedBox(height: 16),
          Text('Open an engagement JSON to begin.',
              style: TextStyle(fontSize: 16, color: Color(0xFFC9D1D9))),
          SizedBox(height: 8),
          Text('Produce one with:  redengine-cli <args> --emit-json engagement.json',
              style: TextStyle(color: Color(0xFF8B95A5))),
        ],
      ),
    );
  }
}

class _SourceBar extends StatelessWidget {
  final Map<String, dynamic> meta;
  final String? path;
  const _SourceBar({required this.meta, required this.path});
  @override
  Widget build(BuildContext context) {
    final mode = (meta['mode'] ?? '-').toString();
    final target = (meta['target'] ?? '-').toString();
    final generated = (meta['generated'] ?? '').toString();
    return Container(
      width: double.infinity,
      color: const Color(0xFF11151B),
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: Wrap(
        spacing: 18,
        runSpacing: 4,
        crossAxisAlignment: WrapCrossAlignment.center,
        children: [
          _kv('mode', mode),
          _kv('target', target),
          if (generated.isNotEmpty) _kv('generated', generated),
          if (path != null) _kv('source', path!),
        ],
      ),
    );
  }

  Widget _kv(String k, String v) => RichText(
        text: TextSpan(
          style: const TextStyle(fontSize: 12, color: Color(0xFFC9D1D9)),
          children: [
            TextSpan(text: '$k ', style: const TextStyle(color: Color(0xFF8B95A5))),
            TextSpan(text: v, style: const TextStyle(fontWeight: FontWeight.w600)),
          ],
        ),
      );
}

class _Tabs extends StatelessWidget {
  final int index;
  final ValueChanged<int> onChanged;
  final List<String> labels;
  const _Tabs({required this.index, required this.onChanged, required this.labels});
  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      color: const Color(0xFF11151B),
      padding: const EdgeInsets.symmetric(horizontal: 8),
      child: Row(
        children: [
          for (var i = 0; i < labels.length; i++)
            Padding(
              padding: const EdgeInsets.all(4),
              child: TextButton(
                onPressed: () => onChanged(i),
                style: TextButton.styleFrom(
                  backgroundColor:
                      i == index ? const Color(0xFF1F2937) : Colors.transparent,
                  foregroundColor:
                      i == index ? Colors.white : const Color(0xFF8B95A5),
                ),
                child: Text(labels[i]),
              ),
            ),
        ],
      ),
    );
  }
}

// --------------------------------------------------------------------------- //
// Dashboard: severity metric cards + hosts table
// --------------------------------------------------------------------------- //
class DashboardView extends StatelessWidget {
  final Engagement eng;
  const DashboardView({super.key, required this.eng});
  @override
  Widget build(BuildContext context) {
    final counts = eng.severityCounts;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Wrap(
          spacing: 12,
          runSpacing: 12,
          children: [
            for (final s in kSevOrder)
              _MetricCard(label: s, value: counts[s] ?? 0, color: sevColor(s)),
            _MetricCard(
                label: 'hosts',
                value: eng.hosts.length,
                color: const Color(0xFFC9D1D9)),
            _MetricCard(
                label: 'attack paths',
                value: eng.attackPaths.length,
                color: const Color(0xFF4C8DFF)),
          ],
        ),
        const SizedBox(height: 24),
        const Text('Hosts',
            style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
        const SizedBox(height: 8),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(8),
            child: _HostsTable(hosts: eng.hosts),
          ),
        ),
        const SizedBox(height: 24),
        if (eng.killchain.isNotEmpty) ...[
          const Text('Kill-chain coverage',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
          const SizedBox(height: 8),
          Card(
            child: Column(
              children: [
                for (final st in eng.killchain)
                  ListTile(
                    dense: true,
                    leading: CircleAvatar(
                      radius: 14,
                      backgroundColor: const Color(0xFF1F2937),
                      child: Text('${st.id}',
                          style: const TextStyle(fontSize: 12)),
                    ),
                    title: Text(st.name),
                    subtitle: Text(st.objective,
                        maxLines: 1, overflow: TextOverflow.ellipsis),
                    trailing: Text(
                        'steps ${st.stagedStepCount} · paths ${st.pathIds.length}',
                        style: const TextStyle(color: Color(0xFF8B95A5))),
                  ),
              ],
            ),
          ),
        ],
      ],
    );
  }
}

class _MetricCard extends StatelessWidget {
  final String label;
  final int value;
  final Color color;
  const _MetricCard(
      {required this.label, required this.value, required this.color});
  @override
  Widget build(BuildContext context) {
    return Container(
      width: 150,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF161B22),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFF21262D)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('$value',
              style: TextStyle(
                  fontSize: 30, fontWeight: FontWeight.bold, color: color)),
          const SizedBox(height: 4),
          Text(label.toUpperCase(),
              style: const TextStyle(
                  fontSize: 11, letterSpacing: 1, color: Color(0xFF8B95A5))),
        ],
      ),
    );
  }
}

class _HostsTable extends StatelessWidget {
  final List<Host> hosts;
  const _HostsTable({required this.hosts});
  @override
  Widget build(BuildContext context) {
    if (hosts.isEmpty) {
      return const Padding(
        padding: EdgeInsets.all(16),
        child: Text('No hosts in this engagement.',
            style: TextStyle(color: Color(0xFF8B95A5))),
      );
    }
    return SingleChildScrollView(
      scrollDirection: Axis.horizontal,
      child: DataTable(
        columnSpacing: 28,
        headingTextStyle: const TextStyle(
            color: Color(0xFF8B95A5), fontWeight: FontWeight.bold, fontSize: 12),
        columns: const [
          DataColumn(label: Text('GRADE')),
          DataColumn(label: Text('HOST')),
          DataColumn(label: Text('IP')),
          DataColumn(label: Text('DEVICE CLASS')),
          DataColumn(label: Text('OS')),
          DataColumn(label: Text('PORTS'), numeric: true),
          DataColumn(label: Text('FINDINGS'), numeric: true),
        ],
        rows: [
          for (final h in hosts)
            DataRow(cells: [
              DataCell(Container(
                width: 28,
                height: 28,
                alignment: Alignment.center,
                decoration: BoxDecoration(
                  color: gradeColor(h.grade).withValues(alpha: 0.18),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Text(h.grade,
                    style: TextStyle(
                        color: gradeColor(h.grade),
                        fontWeight: FontWeight.bold)),
              )),
              DataCell(Text(h.label,
                  style: const TextStyle(fontWeight: FontWeight.w600))),
              DataCell(Text(h.ip.isEmpty ? '-' : h.ip)),
              DataCell(Text(h.deviceClass.isEmpty ? '-' : h.deviceClass,
                  style: const TextStyle(color: Color(0xFF4C8DFF)))),
              DataCell(Text(h.os.isEmpty ? '-' : h.os,
                  style: const TextStyle(color: Color(0xFF8B95A5)))),
              DataCell(Text('${h.openPorts}')),
              DataCell(Text('${h.findingCount}')),
            ]),
        ],
      ),
    );
  }
}

// --------------------------------------------------------------------------- //
// Attack paths: scenario cards -> steps with a Copy command button
// --------------------------------------------------------------------------- //
class AttackPathsView extends StatelessWidget {
  final Engagement eng;
  const AttackPathsView({super.key, required this.eng});
  @override
  Widget build(BuildContext context) {
    if (eng.attackPaths.isEmpty) {
      return const Center(
        child: Text('No attack paths derived for this engagement.',
            style: TextStyle(color: Color(0xFF8B95A5))),
      );
    }
    return ListView.builder(
      padding: const EdgeInsets.all(16),
      itemCount: eng.attackPaths.length,
      itemBuilder: (context, i) => _PathCard(path: eng.attackPaths[i]),
    );
  }
}

class _PathCard extends StatelessWidget {
  final AttackPath path;
  const _PathCard({required this.path});
  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.only(bottom: 14),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(color: sevColor(path.severity).withValues(alpha: 0.5)),
      ),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                _Pill(text: path.id, color: const Color(0xFF8B95A5)),
                const SizedBox(width: 8),
                _Pill(
                    text: path.severity.toUpperCase(),
                    color: sevColor(path.severity)),
                const SizedBox(width: 8),
                _Pill(text: path.kind.toUpperCase(), color: const Color(0xFF4C8DFF)),
                const SizedBox(width: 8),
                Text('conf ${path.confidence} · score ${path.score}',
                    style: const TextStyle(
                        fontSize: 12, color: Color(0xFF8B95A5))),
              ],
            ),
            const SizedBox(height: 8),
            Text(path.name,
                style: const TextStyle(
                    fontSize: 16, fontWeight: FontWeight.bold)),
            if (path.rationale.isNotEmpty) ...[
              const SizedBox(height: 4),
              Text(path.rationale,
                  style: const TextStyle(color: Color(0xFF8B95A5))),
            ],
            const SizedBox(height: 10),
            for (final s in path.steps) _StepTile(step: s),
          ],
        ),
      ),
    );
  }
}

class _StepTile extends StatelessWidget {
  final Step step;
  const _StepTile({required this.step});

  Future<void> _copy(BuildContext context) async {
    // The ONLY side effect this app has: write a staged command to the
    // clipboard. It does not run anything.
    await Clipboard.setData(ClipboardData(text: step.command));
    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          duration: Duration(seconds: 3),
          content: Text(
              'Command copied — run it in YOUR tooling, in authorized scope.'),
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(top: 8),
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: const Color(0xFF11151B),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Expanded(
                child: RichText(
                  text: TextSpan(
                    style: const TextStyle(fontSize: 13, color: Color(0xFFC9D1D9)),
                    children: [
                      TextSpan(
                          text: '${step.order}. ${step.tactic}  ',
                          style: const TextStyle(fontWeight: FontWeight.bold)),
                      TextSpan(
                          text: step.techniqueId,
                          style: const TextStyle(color: Color(0xFFFFC14A))),
                      TextSpan(text: '  ${step.technique}  @ ${step.host}'),
                    ],
                  ),
                ),
              ),
              OutlinedButton.icon(
                onPressed: step.command.isEmpty ? null : () => _copy(context),
                icon: const Icon(Icons.copy, size: 16),
                label: const Text('Copy command'),
              ),
            ],
          ),
          if (step.guidance.isNotEmpty) ...[
            const SizedBox(height: 6),
            Text(step.guidance,
                style: const TextStyle(color: Color(0xFF8B95A5), fontSize: 12)),
          ],
          if (!step.abuse.isEmpty) ...[
            const SizedBox(height: 6),
            if (step.abuse.impact.isNotEmpty)
              _abuseLine('Abuse', step.abuse.impact, const Color(0xFF7BD88F)),
            if (step.abuse.opsec.isNotEmpty)
              _abuseLine('Opsec', step.abuse.opsec, const Color(0xFF8B95A5)),
          ],
          if (step.command.isNotEmpty) ...[
            const SizedBox(height: 8),
            SelectableText(
              step.command,
              style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 12,
                  color: Color(0xFFFFC14A)),
            ),
          ],
        ],
      ),
    );
  }

  Widget _abuseLine(String k, String v, Color color) => Padding(
        padding: const EdgeInsets.only(top: 2),
        child: RichText(
          text: TextSpan(
            style: const TextStyle(fontSize: 12, color: Color(0xFFC9D1D9)),
            children: [
              TextSpan(
                  text: '$k: ',
                  style: TextStyle(color: color, fontWeight: FontWeight.bold)),
              TextSpan(text: v),
            ],
          ),
        ),
      );
}

class _Pill extends StatelessWidget {
  final String text;
  final Color color;
  const _Pill({required this.text, required this.color});
  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.18),
        borderRadius: BorderRadius.circular(6),
      ),
      child: Text(text,
          style: TextStyle(
              color: color, fontSize: 11, fontWeight: FontWeight.bold)),
    );
  }
}
