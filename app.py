import streamlit as st
import pandas as pd
import plotly.express as px
import xml.etree.ElementTree as ET
import io
import zipfile
from datetime import datetime, timedelta

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
                        st.error(f"{uploaded_file.name}内にXMLファイルが見つかりません。")
                        continue
                    for xml_file in xml_files:
                        xml_content = z.read(xml_file).decode('utf-8')
                        all_dfs.append(parse_dmarc_report(xml_content))
            else:
                all_dfs.append(parse_dmarc_report(uploaded_file))
        
        if not all_dfs:
            st.error("有効なDMARCレポートが見つかりませんでした。")
            return
        
        df = pd.concat(all_dfs, ignore_index=True)
        
        # 日付でソート
        df = df.sort_values('date')

        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("配信結果概要")
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
            fig = px.bar(auth_df, x='認証', y='数', title="認証結果の分布")
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

        # ドメインごとの認証結果
        st.write("ドメインごとの認証結果")
        domain_analysis = df.groupby('header_from').agg({
            'dkim_result': lambda x: (x == 'pass').sum() / len(x) * 100,
            'spf_result': lambda x: (x == 'pass').sum() / len(x) * 100,
            'count': 'sum'
        }).reset_index()
        domain_analysis.columns = ['ドメイン', 'DKIM成功率(%)', 'SPF成功率(%)', 'メッセージ数']
        st.dataframe(domain_analysis)

        # DKIM認証の詳細分析
        st.write("DKIM認証の詳細")
        dkim_analysis = df.groupby(['dkim_result', 'dkim_auth_result']).size().reset_index(name='count')
        fig_dkim = px.pie(dkim_analysis, values='count', names='dkim_result', 
                          title='DKIM認証結果',
                          hover_data=['dkim_auth_result'])
        st.plotly_chart(fig_dkim)

        # SPF認証の詳細分析
        st.write("SPF認証の詳細")
        spf_analysis = df.groupby(['spf_result', 'spf_auth_result']).size().reset_index(name='count')
        fig_spf = px.pie(spf_analysis, values='count', names='spf_result', 
                         title='SPF認証結果',
                         hover_data=['spf_auth_result'])
        st.plotly_chart(fig_spf)

        # 認証結果の不一致分析
        st.write("認証結果の不一致分析")
        mismatch_df = df[((df['dkim_result'] == 'fail') & (df['dkim_auth_result'] == 'pass')) |
                         ((df['spf_result'] == 'fail') & (df['spf_auth_result'] == 'pass'))]
        if not mismatch_df.empty:
            st.dataframe(mismatch_df[['source_ip', 'count', 'dkim_result', 'dkim_auth_result', 'spf_result', 'spf_auth_result', 'header_from']])
        else:
            st.info("認証結果の不一致は見つかりませんでした。")

if __name__ == "__main__":
    main()