# list1 = ["Adware_img", "Backdoor", 'Botnet', 'Downloader', 'Keylogger', 'Ransomware', 'Rootkit',
#          'Spyware', 'Trojan', 'Virus', 'Worm']
#
# list2 = ['exe', 'Worm.Vobfus']
#
# list2_updated = []
# for item in list2:
#     if "." in item:
#         item_part = item.split(".")[0]
#         list2_updated.append(item_part)
#     else:
#         list2_updated.append(item)
#
# matching_items = []
# for item1 in list1:
#     for item2 in list2_updated:
#         if item1[0].isupper() and item1.lower() == item2.lower():
#             matching_items.append(item1)
#
# print("Matching items:", matching_items)


fam_labels = ["Adware_img", "Backdoor", 'Botnet', 'Downloader', 'Keylogger', 'Ransomware', 'Rootkit',
              'Spyware', 'Trojan', 'Virus', 'Worm']
list2 = ["exe", "Worm.Vobfus"]

matching_items = []
for item1 in fam_labels:
    for item2 in list2:
        if item1[0].isupper() and item1.lower() == item2.split(".")[0].lower():
            matching_items.append(item1)

print(f"Matching items: {matching_items}")

