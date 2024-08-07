import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import xml.etree.ElementTree as ET
import io
import zipfile
from datetime import datetime, timedelta
import base64
from jinja2 import Template

def parse_dmarc_report(content):
    if not isinstance(content, str):
        content = content.getvalue().decode('utf-8')
    
    root = ET.fromstring(content)
    
    # date_rangeから日付を取得
    begin_date = datetime.fromtimestamp(int(root.find('.//date_range/begin').text))
    end_date = datetime.fromtimestamp(int(root.find('.//date_range/end').text))
    report_date = begin_date.date()  # レポートの日付として開始日を使用

    data = []
    for record in root.findall('.//record'):
        row = {}
        row['date'] = report_date  # 新しく追加
        row['source_ip'] = record.find('.//source_ip').text
        row['count'] = int(record.find('.//count').text)
        row['disposition'] = record.find('.//policy_evaluated/disposition').text
        row['dkim_result'] = record.find('.//policy_evaluated/dkim').text
        row['spf_result'] = record.find('.//policy_evaluated/spf').text
        row['header_from'] = record.find('.//identifiers/header_from').text
        
        dkim = record.find('.//auth_results/dkim')
        if dkim is not None:
            row['dkim_domain'] = dkim.find('domain').text
            row['dkim_auth_result'] = dkim.find('result').text
        else:
            row['dkim_domain'] = None
            row['dkim_auth_result'] = None
        
        spf = record.find('.//auth_results/spf')
        if spf is not None:
            row['spf_domain'] = spf.find('domain').text
            row['spf_auth_result'] = spf.find('result').text
        else:
            row['spf_domain'] = None
            row['spf_auth_result'] = None
        
        data.append(row)
    
    df = pd.DataFrame(data)
    return df

def plot_to_html(fig):
    return fig.to_html(full_html=False, include_plotlyjs='cdn')

def dataframe_to_html(df):
    html = df.to_html(classes='min-w-full divide-y divide-gray-200', index=False, escape=False, table_id='dataTable')
    
    # テーブルヘッダーとセルにスタイルを追加
    html = html.replace('<th>', '<th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">')
    html = html.replace('<td>', '<td class="px-4 py-2 whitespace-nowrap text-sm text-gray-900">')
    
    return html

def generate_html_report(df, dkim_fig, spf_fig, domain_analysis, mismatch_df, total_messages, pass_rate, problem_ips):
    # 分析期間の計算
    start_date = df['date'].min()
    end_date = df['date'].max()
    
    template = Template("""
    <!DOCTYPE html>
    <html lang="ja">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>DMARCレポート分析</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-100 text-gray-900 font-sans">
        <div class="container mx-auto px-4 py-8">
            <h1 class="text-3xl font-bold mb-8">DMARCレポート分析</h1>
            
            <div class="bg-white shadow rounded-lg p-6 mb-8">
                <h2 class="text-2xl font-semibold mb-4">配信結果概要</h2>
                <p class="mb-2">分析期間: <span class="font-bold">{{ start_date.strftime('%Y年%m月%d日') }} 〜 {{ end_date.strftime('%Y年%m月%d日') }}</span></p>
                <p class="mb-2">総メッセージ数: <span class="font-bold">{{ total_messages }}</span></p>
                <p>配信成功率: <span class="font-bold">{{ "%.2f"|format(pass_rate) }}%</span></p>
            </div>
            
            <div class="bg-white shadow rounded-lg p-6 mb-8">
                <h2 class="text-2xl font-semibold mb-4">問題のある送信元IP</h2>
                {% if problem_ips %}
                    <div class="overflow-x-auto">
                        {{ problem_ips | safe }}
                    </div>
                {% else %}
                    <p class="text-gray-600">問題のある送信元IPは見つかりませんでした。</p>
                {% endif %}
            </div>
            
            <div class="bg-white shadow rounded-lg p-6 mb-8">
                <h2 class="text-2xl font-semibold mb-4">認証結果の詳細分析</h2>
                
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div>
                        <h3 class="text-xl font-semibold mb-2">DKIM認証の詳細</h3>
                        <div>{{ dkim_chart | safe }}</div>
                    </div>
                    <div>
                        <h3 class="text-xl font-semibold mb-2">SPF認証の詳細</h3>
                        <div>{{ spf_chart | safe }}</div>
                    </div>
                </div>
                
                <h3 class="text-xl font-semibold my-4">ドメインごとの認証結果</h3>
                <div class="overflow-x-auto mb-6">{{ domain_analysis | safe }}</div>
                
                <h3 class="text-xl font-semibold mb-2">認証結果の不一致分析</h3>
                {% if mismatch_df %}
                    <div class="overflow-x-auto">
                        {{ mismatch_df | safe }}
                    </div>
                {% else %}
                    <p class="text-gray-600">認証結果の不一致は見つかりませんでした。</p>
                {% endif %}
            </div>
            
            <div class="bg-white shadow rounded-lg p-6">
                <h2 class="text-2xl font-semibold mb-4">詳細結果</h2>
                <div class="overflow-x-auto">
                    {{ detailed_results | safe }}
                </div>
            </div>
        </div>
    </body>
    </html>
    """)
    
    html = template.render(
        start_date=start_date,
        end_date=end_date,
        total_messages=total_messages,
        pass_rate=pass_rate,
        problem_ips=dataframe_to_html(problem_ips) if not problem_ips.empty else None,
        dkim_chart=plot_to_html(dkim_fig),
        spf_chart=plot_to_html(spf_fig),
        domain_analysis=dataframe_to_html(domain_analysis),
        mismatch_df=dataframe_to_html(mismatch_df) if not mismatch_df.empty else None,
        detailed_results=dataframe_to_html(df)
    )
    
    return html

def get_table_download_link(html):
    """Generates a link allowing the html to be downloaded"""
    b64 = base64.b64encode(html.encode()).decode()
    return f'<a href="data:text/html;base64,{b64}" download="dmarc_report.html">Download HTML report</a>'

def main():
    st.title("DMARCレポート分析")

    uploaded_files = st.file_uploader("DMARCレポートをアップロード (XML または ZIP)", type=["xml", "zip"], accept_multiple_files=True)
    
    if uploaded_files:
        all_dfs = []
        for uploaded_file in uploaded_files:
            if uploaded_file.type == "application/zip":
                with zipfile.ZipFile(uploaded_file) as z:
                    xml_files = [f for f in z.namelist() if f.endswith('.xml')]
                    if not xml_files:
                        st.error(f"{uploaded_file.name}内にXMLファルが見つかりません。")
                        continue
                    for xml_file in xml_files:
                        xml_content = z.read(xml_file).decode('utf-8')
                        all_dfs.append(parse_dmarc_report(xml_content))
            else:
                all_dfs.append(parse_dmarc_report(uploaded_file))
        
        if not all_dfs:
            st.error("有効なDMARCレポート見つかりませんでした。")
            return
        
        df = pd.concat(all_dfs, ignore_index=True)
        
        # 日付でソート
        df = df.sort_values('date')

        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("配信結果概要")
            start_date = df['date'].min()
            end_date = df['date'].max()
            st.write(f"分析期間: {start_date.strftime('%Y年%m月%d日')} 〜 {end_date.strftime('%Y年%m月%d日')}")
            total_messages = df['count'].sum()
            st.metric("総メッセージ数", total_messages)
            
            pass_rate = (df[df['disposition'] == 'none']['count'].sum() / total_messages) * 100
            st.metric("配信成功率", f"{pass_rate:.2f}%")

        with col2:
            st.subheader("認証結果")
            auth_results = {
                'DKIM Pass': (df['dkim_result'] == 'pass').sum(),
                'DKIM Fail': (df['dkim_result'] == 'fail').sum(),
                'SPF Pass': (df['spf_result'] == 'pass').sum(),
                'SPF Fail': (df['spf_result'] == 'fail').sum()
            }
            auth_df = pd.DataFrame(list(auth_results.items()), columns=['認証', '数'])
            fig = go.Figure(data=[go.Pie(
                labels=auth_df['認証'],
                values=auth_df['数'],
                marker=dict(colors=['#66c2a5', '#fc8d62', '#8da0cb', '#e78ac3'])
            )])
            fig.update_layout(title='認証結果の分布')
            st.plotly_chart(fig)

        st.subheader("問題のある送信元IP")
        problem_ips = df[(df['disposition'] != 'none') | (df['dkim_result'] == 'fail') | (df['spf_result'] == 'fail')]
        if not problem_ips.empty:
            st.dataframe(problem_ips[['source_ip', 'count', 'disposition', 'dkim_result', 'spf_result']])
        else:
            st.info("問題のある送信元IPは見つかりませんでした。")

        st.subheader("詳細結果")
        st.dataframe(df)

        st.subheader("認証結果の詳細分析")

        col1, col2 = st.columns(2)
        
        with col1:
            # DKIM認証の詳細分析
            dkim_analysis = df.groupby(['dkim_result', 'dkim_auth_result']).size().reset_index(name='count')
            fig_dkim = go.Figure(data=[go.Pie(
                labels=dkim_analysis['dkim_result'],
                values=dkim_analysis['count'],
                hovertext=dkim_analysis['dkim_auth_result'],
                textinfo='percent+label',
                marker=dict(colors=['#66c2a5', '#fc8d62', '#8da0cb', '#e78ac3'])
            )])
            fig_dkim.update_layout(title='DKIM認証結果')
            st.plotly_chart(fig_dkim)
        
        with col2:
            # SPF認証の詳細分析
            spf_analysis = df.groupby(['spf_result', 'spf_auth_result']).size().reset_index(name='count')
            fig_spf = go.Figure(data=[go.Pie(
                labels=spf_analysis['spf_result'],
                values=spf_analysis['count'],
                hovertext=spf_analysis['spf_auth_result'],
                textinfo='percent+label',
                marker=dict(colors=['#66c2a5', '#fc8d62', '#8da0cb', '#e78ac3'])
            )])
            fig_spf.update_layout(title='SPF認証結果')
            st.plotly_chart(fig_spf)

        # ドメインごとの認証結果
        st.write("ドメインごとの認証結果")
        domain_analysis = df.groupby('header_from').agg({
            'dkim_result': lambda x: (x == 'pass').sum() / len(x) * 100,
            'spf_result': lambda x: (x == 'pass').sum() / len(x) * 100,
            'count': 'sum'
        }).reset_index()
        domain_analysis.columns = ['ドメイン', 'DKIM成功率(%)', 'SPF成功率(%)', 'メッセージ数']
        st.dataframe(domain_analysis)

        # 認証結果の不一致分析
        st.write("認証結果の不一致分析")
        mismatch_df = df[((df['dkim_result'] == 'fail') & (df['dkim_auth_result'] == 'pass')) |
                         ((df['spf_result'] == 'fail') & (df['spf_auth_result'] == 'pass'))]
        if not mismatch_df.empty:
            st.dataframe(mismatch_df[['source_ip', 'count', 'dkim_result', 'dkim_auth_result', 'spf_result', 'spf_auth_result', 'header_from']])
        else:
            st.info("認証結果の不一致は見つかりませんでした。")

        # HTMLレポートの生成とダウンロードリンクの表示
        html_report = generate_html_report(df, fig_dkim, fig_spf, domain_analysis, mismatch_df, total_messages, pass_rate, problem_ips)
        st.markdown(get_table_download_link(html_report), unsafe_allow_html=True)

if __name__ == "__main__":
    main()