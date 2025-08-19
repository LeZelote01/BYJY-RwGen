#!/usr/bin/env python3
"""
BYJY-RwGen Research Data Analyzer
Advanced analysis tool for defensive cybersecurity research
FOR RESEARCH PURPOSES ONLY
"""

import sqlite3
import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from datetime import datetime, timedelta
import argparse
import sys
from pathlib import Path

class ResearchDataAnalyzer:
    def __init__(self, db_path="/app/c2_server/research_c2.db"):
        self.db_path = db_path
        self.conn = None
        self.connect_database()
    
    def connect_database(self):
        """Connect to the research database"""
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
            print(f"✓ Connected to database: {self.db_path}")
        except Exception as e:
            print(f"✗ Failed to connect to database: {e}")
            sys.exit(1)
    
    def analyze_victim_patterns(self):
        """Analyze victim infection patterns"""
        print("\n=== Victim Pattern Analysis ===")
        
        query = """
        SELECT 
            victim_id,
            hostname,
            os_version,
            country,
            files_encrypted,
            ransom_amount,
            payment_status,
            datetime(first_seen) as first_seen,
            datetime(last_heartbeat) as last_heartbeat
        FROM victims
        ORDER BY first_seen DESC
        """
        
        df = pd.read_sql_query(query, self.conn)
        
        if df.empty:
            print("No victim data found")
            return None
        
        # Basic statistics
        print(f"Total Victims: {len(df)}")
        print(f"Average Files Encrypted: {df['files_encrypted'].mean():.1f}")
        print(f"Average Ransom Amount: {df['ransom_amount'].mean():.2f} BTC")
        
        # Geographic distribution
        country_dist = df['country'].value_counts()
        print(f"\nGeographic Distribution:")
        for country, count in country_dist.items():
            print(f"  {country}: {count} victims")
        
        # OS distribution
        os_dist = df['os_version'].value_counts()
        print(f"\nOperating System Distribution:")
        for os, count in os_dist.items():
            print(f"  {os}: {count} victims")
        
        # Payment status
        payment_dist = df['payment_status'].value_counts()
        print(f"\nPayment Status:")
        for status, count in payment_dist.items():
            print(f"  {status}: {count} victims")
        
        return df
    
    def analyze_attack_timeline(self):
        """Analyze attack timeline and infection rates"""
        print("\n=== Attack Timeline Analysis ===")
        
        query = """
        SELECT 
            date(first_seen) as infection_date,
            COUNT(*) as infections_per_day,
            AVG(files_encrypted) as avg_files_per_day,
            SUM(files_encrypted) as total_files_per_day
        FROM victims
        WHERE first_seen IS NOT NULL
        GROUP BY date(first_seen)
        ORDER BY infection_date
        """
        
        df = pd.read_sql_query(query, self.conn)
        
        if df.empty:
            print("No timeline data available")
            return None
        
        print(f"Analysis period: {df['infection_date'].min()} to {df['infection_date'].max()}")
        print(f"Peak infection day: {df.loc[df['infections_per_day'].idxmax(), 'infection_date']} ({df['infections_per_day'].max()} infections)")
        print(f"Total files encrypted: {df['total_files_per_day'].sum()}")
        
        return df
    
    def analyze_payment_behavior(self):
        """Analyze payment patterns and timing"""
        print("\n=== Payment Behavior Analysis ===")
        
        query = """
        SELECT 
            p.*,
            v.hostname,
            v.country,
            v.files_encrypted,
            julianday(p.received_at) - julianday(v.first_seen) as payment_delay_days
        FROM payments p
        JOIN victims v ON p.victim_id = v.victim_id
        WHERE p.payment_received = 1
        """
        
        df = pd.read_sql_query(query, self.conn)
        
        if df.empty:
            print("No payment data available")
            return None
        
        print(f"Total Payments: {len(df)}")
        print(f"Total Revenue: {df['amount_btc'].sum():.2f} BTC")
        print(f"Average Payment Amount: {df['amount_btc'].mean():.2f} BTC")
        print(f"Average Payment Delay: {df['payment_delay_days'].mean():.1f} days")
        
        # Payment timing analysis
        quick_payments = df[df['payment_delay_days'] <= 1]
        slow_payments = df[df['payment_delay_days'] > 3]
        
        print(f"Quick Payments (<24h): {len(quick_payments)} ({len(quick_payments)/len(df)*100:.1f}%)")
        print(f"Slow Payments (>3d): {len(slow_payments)} ({len(slow_payments)/len(df)*100:.1f}%)")
        
        return df
    
    def analyze_system_performance(self):
        """Analyze system performance metrics"""
        print("\n=== System Performance Analysis ===")
        
        query = """
        SELECT 
            victim_id,
            files_total,
            files_processed,
            files_failed,
            processing_time_seconds,
            throughput_files_per_sec,
            average_file_size_mb,
            datetime(timestamp) as processing_time
        FROM decryption_performance
        ORDER BY timestamp DESC
        """
        
        df = pd.read_sql_query(query, self.conn)
        
        if df.empty:
            print("No performance data available")
            return None
        
        print(f"Total Processing Sessions: {len(df)}")
        print(f"Average Processing Time: {df['processing_time_seconds'].mean():.1f} seconds")
        print(f"Average Throughput: {df['throughput_files_per_sec'].mean():.1f} files/sec")
        print(f"Average Success Rate: {(df['files_processed'] / df['files_total']).mean()*100:.1f}%")
        print(f"Average File Size: {df['average_file_size_mb'].mean():.2f} MB")
        
        return df
    
    def analyze_system_events(self):
        """Analyze system events and security incidents"""
        print("\n=== System Events Analysis ===")
        
        query = """
        SELECT 
            event_type,
            COUNT(*) as event_count,
            severity,
            datetime(timestamp) as event_time
        FROM system_audit_log
        GROUP BY event_type, severity
        ORDER BY event_count DESC
        """
        
        df = pd.read_sql_query(query, self.conn)
        
        if df.empty:
            print("No system events logged")
            return None
        
        print("Event Distribution:")
        for _, row in df.iterrows():
            print(f"  {row['event_type']} ({row['severity']}): {row['event_count']} events")
        
        # Security events
        security_query = """
        SELECT 
            event_type,
            event_data,
            severity,
            datetime(timestamp) as event_time
        FROM system_audit_log
        WHERE severity IN ('warning', 'error')
        ORDER BY timestamp DESC
        LIMIT 10
        """
        
        security_df = pd.read_sql_query(security_query, self.conn)
        
        if not security_df.empty:
            print(f"\nRecent Security Events ({len(security_df)}):")
            for _, row in security_df.iterrows():
                print(f"  [{row['event_time']}] {row['event_type']} - {row['severity'].upper()}")
        
        return df
    
    def generate_attack_simulation_report(self):
        """Generate comprehensive attack simulation report"""
        print("\n" + "="*60)
        print("ATTACK SIMULATION ANALYSIS REPORT")
        print("="*60)
        
        report = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "database": self.db_path,
                "analysis_type": "Defensive Research",
                "purpose": "Ransomware Pattern Analysis"
            },
            "findings": {},
            "metrics": {},
            "recommendations": []
        }
        
        # Analyze all components
        victim_df = self.analyze_victim_patterns()
        timeline_df = self.analyze_attack_timeline()
        payment_df = self.analyze_payment_behavior()
        performance_df = self.analyze_system_performance()
        events_df = self.analyze_system_events()
        
        # Generate insights
        if victim_df is not None:
            report["metrics"]["total_victims"] = len(victim_df)
            report["metrics"]["avg_files_encrypted"] = float(victim_df['files_encrypted'].mean())
            report["metrics"]["geographic_spread"] = len(victim_df['country'].unique())
            
            report["findings"]["victim_patterns"] = {
                "most_targeted_os": victim_df['os_version'].mode().iloc[0] if not victim_df.empty else None,
                "highest_file_encryption": int(victim_df['files_encrypted'].max()),
                "payment_compliance_rate": float((victim_df['payment_status'] == 'paid').mean() * 100)
            }
        
        if payment_df is not None:
            report["metrics"]["total_revenue"] = float(payment_df['amount_btc'].sum())
            report["metrics"]["avg_payment_time"] = float(payment_df['payment_delay_days'].mean())
            
            report["findings"]["payment_patterns"] = {
                "quick_payment_rate": float(len(payment_df[payment_df['payment_delay_days'] <= 1]) / len(payment_df) * 100),
                "avg_ransom_amount": float(payment_df['amount_btc'].mean()),
                "payment_timing_variance": float(payment_df['payment_delay_days'].std())
            }
        
        if performance_df is not None:
            report["metrics"]["avg_processing_time"] = float(performance_df['processing_time_seconds'].mean())
            report["metrics"]["system_efficiency"] = float((performance_df['files_processed'] / performance_df['files_total']).mean() * 100)
        
        # Generate recommendations
        self._generate_defense_recommendations(report, victim_df, payment_df, performance_df)
        
        return report
    
    def _generate_defense_recommendations(self, report, victim_df, payment_df, performance_df):
        """Generate specific defense recommendations based on analysis"""
        
        recommendations = []
        
        # Based on victim patterns
        if victim_df is not None:
            avg_files = victim_df['files_encrypted'].mean()
            if avg_files > 1000:
                recommendations.append({
                    "category": "Behavioral Detection",
                    "priority": "HIGH",
                    "description": f"High file encryption rate detected (avg: {avg_files:.0f} files). Implement rapid file modification detection.",
                    "implementation": "EDR rules for >100 file operations per minute"
                })
            
            os_diversity = len(victim_df['os_version'].unique())
            if os_diversity > 2:
                recommendations.append({
                    "category": "Cross-Platform Protection",
                    "priority": "MEDIUM", 
                    "description": f"Multi-OS targeting detected ({os_diversity} different OS). Ensure cross-platform security controls.",
                    "implementation": "Unified endpoint protection across all OS types"
                })
        
        # Based on payment patterns
        if payment_df is not None:
            quick_payment_rate = len(payment_df[payment_df['payment_delay_days'] <= 1]) / len(payment_df)
            if quick_payment_rate > 0.3:
                recommendations.append({
                    "category": "Incident Response",
                    "priority": "HIGH",
                    "description": f"High quick payment rate ({quick_payment_rate*100:.1f}%). Improve rapid response capabilities.",
                    "implementation": "24/7 SOC with 1-hour response time SLA"
                })
        
        # Based on system performance
        if performance_df is not None:
            avg_throughput = performance_df['throughput_files_per_sec'].mean()
            if avg_throughput > 10:
                recommendations.append({
                    "category": "Performance Monitoring",
                    "priority": "MEDIUM",
                    "description": f"High encryption throughput detected ({avg_throughput:.1f} files/sec). Monitor for performance anomalies.",
                    "implementation": "Baseline performance monitoring with alerts on 10x normal activity"
                })
        
        report["recommendations"] = recommendations
    
    def export_analysis_data(self, output_dir="/tmp/research_analysis"):
        """Export analysis data for external processing"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        print(f"\nExporting analysis data to: {output_path}")
        
        # Export all tables as CSV
        tables = [
            'victims',
            'payments', 
            'system_audit_log',
            'decryption_performance',
            'commands',
            'exfiltrated_data'
        ]
        
        for table in tables:
            try:
                query = f"SELECT * FROM {table}"
                df = pd.read_sql_query(query, self.conn)
                
                if not df.empty:
                    csv_path = output_path / f"{table}_data.csv"
                    df.to_csv(csv_path, index=False)
                    print(f"  ✓ Exported {table}: {len(df)} records -> {csv_path}")
                else:
                    print(f"  - {table}: No data")
                    
            except Exception as e:
                print(f"  ✗ Failed to export {table}: {e}")
        
        # Generate summary report
        report = self.generate_attack_simulation_report()
        report_path = output_path / "analysis_report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"  ✓ Analysis report -> {report_path}")
        
        return output_path
    
    def create_visualizations(self, output_dir="/tmp/research_analysis"):
        """Create visualization charts for analysis"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        print(f"\nGenerating visualizations in: {output_path}")
        
        try:
            # Set style
            plt.style.use('seaborn-v0_8')
            
            # Victim geographic distribution
            victim_query = "SELECT country, COUNT(*) as count FROM victims GROUP BY country"
            victim_df = pd.read_sql_query(victim_query, self.conn)
            
            if not victim_df.empty:
                plt.figure(figsize=(10, 6))
                plt.bar(victim_df['country'], victim_df['count'])
                plt.title('Geographic Distribution of Simulated Victims')
                plt.xlabel('Country')
                plt.ylabel('Number of Victims')
                plt.xticks(rotation=45)
                plt.tight_layout()
                plt.savefig(output_path / 'victim_geographic_distribution.png')
                plt.close()
                print("  ✓ Geographic distribution chart")
            
            # Payment timeline
            payment_query = """
            SELECT date(received_at) as payment_date, COUNT(*) as payments_count
            FROM payments 
            WHERE payment_received = 1 
            GROUP BY date(received_at)
            ORDER BY payment_date
            """
            payment_df = pd.read_sql_query(payment_query, self.conn)
            
            if not payment_df.empty:
                plt.figure(figsize=(12, 6))
                payment_df['payment_date'] = pd.to_datetime(payment_df['payment_date'])
                plt.plot(payment_df['payment_date'], payment_df['payments_count'], marker='o')
                plt.title('Payment Timeline Analysis')
                plt.xlabel('Date')
                plt.ylabel('Number of Payments')
                plt.xticks(rotation=45)
                plt.tight_layout()
                plt.savefig(output_path / 'payment_timeline.png')
                plt.close()
                print("  ✓ Payment timeline chart")
            
            # System performance metrics
            perf_query = "SELECT throughput_files_per_sec, processing_time_seconds FROM decryption_performance"
            perf_df = pd.read_sql_query(perf_query, self.conn)
            
            if not perf_df.empty:
                plt.figure(figsize=(10, 6))
                plt.scatter(perf_df['processing_time_seconds'], perf_df['throughput_files_per_sec'])
                plt.title('System Performance Analysis')
                plt.xlabel('Processing Time (seconds)')
                plt.ylabel('Throughput (files/sec)')
                plt.tight_layout()
                plt.savefig(output_path / 'system_performance.png')
                plt.close()
                print("  ✓ Performance analysis chart")
                
        except ImportError:
            print("  ! Matplotlib/Seaborn not available, skipping visualizations")
        except Exception as e:
            print(f"  ✗ Error generating visualizations: {e}")
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()

def main():
    parser = argparse.ArgumentParser(
        description='BYJY-RwGen Research Data Analyzer - FOR RESEARCH PURPOSES ONLY'
    )
    parser.add_argument('--database', '-d', 
                       default='/app/c2_server/research_c2.db',
                       help='Path to research database')
    parser.add_argument('--output', '-o',
                       default='/tmp/research_analysis', 
                       help='Output directory for analysis')
    parser.add_argument('--export', action='store_true',
                       help='Export raw data as CSV files')
    parser.add_argument('--visualize', action='store_true',
                       help='Generate visualization charts')
    parser.add_argument('--report-only', action='store_true',
                       help='Generate report only, no detailed analysis')
    
    args = parser.parse_args()
    
    print("BYJY-RwGen Research Data Analyzer")
    print("FOR DEFENSIVE CYBERSECURITY RESEARCH ONLY")
    print("=" * 50)
    
    # Initialize analyzer
    analyzer = ResearchDataAnalyzer(args.database)
    
    try:
        if args.report_only:
            # Quick report generation
            report = analyzer.generate_attack_simulation_report()
            
            report_path = Path(args.output) / "quick_analysis_report.json"
            report_path.parent.mkdir(exist_ok=True)
            
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2)
            
            print(f"\nQuick analysis report saved: {report_path}")
            
        else:
            # Full analysis
            analyzer.analyze_victim_patterns()
            analyzer.analyze_attack_timeline()
            analyzer.analyze_payment_behavior()
            analyzer.analyze_system_performance()
            analyzer.analyze_system_events()
            
            # Generate comprehensive report
            report = analyzer.generate_attack_simulation_report()
            
            if args.export:
                analyzer.export_analysis_data(args.output)
            
            if args.visualize:
                analyzer.create_visualizations(args.output)
        
        print("\n" + "="*60)
        print("ANALYSIS COMPLETE")
        print("="*60)
        print("This analysis is for defensive cybersecurity research purposes only.")
        print("Use findings to improve detection capabilities and incident response.")
        
    finally:
        analyzer.close()

if __name__ == "__main__":
    main()