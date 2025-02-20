import pandas as pd
import warnings

def convert_xlsx_to_csv(input_file, output_file, encoding="utf-16"):  # Ändra till "utf-8" om du behöver
    try:
        # Läser in Excel-filen och tvingar alla kolumner att läsas som strängar
        df = pd.read_excel(input_file, dtype=str)

        # Sparar DataFrame som CSV med önskad kodning
        df.to_csv(output_file, index=False, encoding=encoding, sep=';', quotechar='"')
        print(f"Filen har sparats som {output_file} med kodning {encoding}.")
    except Exception as e:
        print(f"Ett fel uppstod: {e}")

# Ange sökvägar och kodning
input_file = "UP_2025-01-15.xlsx"  # Ersätt med din filsökväg
output_file = "New_utf_UP_2025-01-15.csv"  # Ange önskad utdataväg
encoding = "utf-16"  # Ändra till "utf-8" om du behöver

convert_xlsx_to_csv(input_file, output_file, encoding)

warnings.filterwarnings("ignore", category=UserWarning, module="openpyxl")
