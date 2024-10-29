# MIT License
#
# Copyright (c) 2024 Saket Upadhyay
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


import argparse
import json
import os

import pandas as pd
import seaborn as sns
from matplotlib import pyplot as plt
from tqdm import tqdm

# Import targets
from targets import FROM_YEAR, TO_YEAR, PRODUCTS, show_plot_title

# Global data vars. Don't change.
number_of_jsons = 0
number_of_vulns_in_target = 0
VULNERABILITY_TYPE_BY_YEAR = dict()
PRODUCTS = [s.lower() for s in PRODUCTS]
LOG_YEARS = [str(i) for i in range(FROM_YEAR, TO_YEAR + 1)]
JSON_FILE_LIST = []


def find_json_files(base_directory):
  global number_of_jsons
  global number_of_vulns_in_target
  global VULNERABILITY_TYPE_BY_YEAR
  # Populating files to process
  for year_folder in os.listdir(base_directory):
    year_path = os.path.join(base_directory, year_folder)
    if str(year_folder) not in VULNERABILITY_TYPE_BY_YEAR:
      VULNERABILITY_TYPE_BY_YEAR[str(year_folder)] = dict()
    if os.path.isdir(year_path) and year_folder.isdigit() and len(year_folder) == 4 and year_folder in LOG_YEARS:
      for subfolder in os.listdir(year_path):
        subfolder_path = os.path.join(year_path, subfolder)
        if os.path.isdir(subfolder_path):
          for file in os.listdir(subfolder_path):
            if file.endswith('.json'):
              number_of_jsons += 1
              json_file_path = os.path.join(subfolder_path, file)
              JSON_FILE_LIST.append(json_file_path)

  print(f"[i] Total log files found = {number_of_jsons}")

  # Processing files
  for json_file_path in tqdm(JSON_FILE_LIST):
    if json_file_path.split('/')[0] == '.':
      year = int(json_file_path.split('/')[3])
    else:
      year = int(json_file_path.split('/')[2])

    with open(json_file_path, 'r') as json_file:
      try:
        data = json.load(json_file)

        if ("containers" in data and "cna" in data["containers"] and "affected" in data["containers"][
          "cna"] and "problemTypes" in data["containers"]["cna"]):

          affected_list = data["containers"]["cna"]["affected"]
          problem_types = data["containers"]["cna"]["problemTypes"]

          if isinstance(affected_list, list):
            for item in affected_list:
              if isinstance(item, dict) and "product" in item:
                if item["product"].lower() in PRODUCTS:
                  number_of_vulns_in_target += 1
                  if isinstance(problem_types, list):
                    for prob in problem_types:
                      if isinstance(prob["descriptions"], list):
                        for desc in prob["descriptions"]:
                          if str(desc["description"]).lower() not in VULNERABILITY_TYPE_BY_YEAR[str(year)]:
                            VULNERABILITY_TYPE_BY_YEAR[str(year)][str(desc["description"]).lower()] = 0
                          VULNERABILITY_TYPE_BY_YEAR[str(year)][str(desc["description"]).lower()] += 1


      except json.JSONDecodeError as e:
        print(f"Error reading JSON file: {e}")


def plot_top_10_bar_graph(vulnerability_data):
  if not vulnerability_data:
    print("[!!] No vulnerability data to plot.")
    return

  flattened_data = []
  for year, vulnerabilities in vulnerability_data.items():
    for vulnerability, count in vulnerabilities.items():
      flattened_data.append((year, vulnerability, count))

  df = pd.DataFrame(flattened_data, columns=['Year', 'Vulnerability Type', 'Count'])

  top_vulnerabilities = df.groupby('Vulnerability Type')['Count'].sum().nlargest(10).index
  filtered_df = df[df['Vulnerability Type'].isin(top_vulnerabilities)]

  bar_data = filtered_df.groupby(['Vulnerability Type', 'Year'])['Count'].sum().unstack().fillna(0)

  # Plotting
  bar_data.plot(kind='bar', stacked=True, figsize=(15, 15))
  if show_plot_title:
    plt.title('Top 10 Vulnerabilities by Type Across Years')
  plt.ylabel('Count')
  plt.yscale('log')
  plt.xlabel('Vulnerability Type')
  plt.legend(title='Year')
  plt.tight_layout()
  print(f"[*] Saving stack bar for {PRODUCTS} from {FROM_YEAR} to {TO_YEAR}")
  plt.savefig(f"{PRODUCTS[0]}-top10-stackbar-{FROM_YEAR}-{TO_YEAR}.png", dpi=600)
  print("[*] Done.")
  plt.close()


def plot_top_10_heatmap(vulnerability_data):
  if not vulnerability_data:
    print("[!!] No vulnerability data to plot.")
    return

  flattened_data = []
  for year, vulnerabilities in vulnerability_data.items():
    for vulnerability, count in vulnerabilities.items():
      flattened_data.append((year, vulnerability, count))

  df = pd.DataFrame(flattened_data, columns=['Year', 'Vulnerability Type', 'Count'])

  top_vulnerabilities = df.groupby('Vulnerability Type')['Count'].sum().nlargest(10).index
  filtered_df = df[df['Vulnerability Type'].isin(top_vulnerabilities)]

  heatmap_data = filtered_df.pivot(index="Year", columns="Vulnerability Type", values="Count").fillna(0)

  plt.figure(figsize=(15, 10))
  sns.heatmap(heatmap_data, annot=True, cmap='YlGnBu', cbar=True, fmt='.0f')
  if show_plot_title:
    plt.title('Top 10 Vulnerabilities by Type Across Years')
  plt.ylabel('Year')
  plt.yticks(rotation=0)
  plt.xlabel('Vulnerability Type')
  plt.tight_layout()
  print(f"[*] Saving heatmap for {PRODUCTS} from {FROM_YEAR} to {TO_YEAR}")
  plt.savefig(f"{PRODUCTS[0]}-top10-heatmap-{FROM_YEAR}-{TO_YEAR}.png", dpi=600)
  plt.close()
  print("[*] Done.")


if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='Process CVE LIST v5 JSON files.')
  parser.add_argument('base_directory', type=str, help='Path to (cvelistV5/cves) folder')
  args = parser.parse_args()
  print(f"[i] Target Years = {LOG_YEARS}")
  print(f"[i] Target Products = {PRODUCTS}")
  print("[*] Processing CVE LIST JSON files...")
  find_json_files(args.base_directory)
  print(f"Vulnerabilities in target product(s) = {number_of_vulns_in_target}")
  print("[*] Sorting by instances.")
  for year_k, year_val_dict in VULNERABILITY_TYPE_BY_YEAR.items():
    VULNERABILITY_TYPE_BY_YEAR[year_k] = dict(
      sorted(VULNERABILITY_TYPE_BY_YEAR[year_k].items(), key=lambda item: item[1], reverse=True))
  print("[*] Done.")

  plot_top_10_bar_graph(VULNERABILITY_TYPE_BY_YEAR)
  plot_top_10_heatmap(VULNERABILITY_TYPE_BY_YEAR)
