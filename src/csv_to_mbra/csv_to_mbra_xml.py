from uuid import uuid4
from xml.etree.ElementTree import SubElement
from zipfile import ZipFile

import pandas as pd
from lxml import etree as et

# Import to dataframe
data = pd.read_csv('./src/data/top_texas_producers.csv', keep_default_na=False)


def create_node(archive_element, layer_uuid,
                long, lat, name, threat, vuln, consequence,
                prevention_cost, response_cost, link_node_id, description="",
                node_type="na_node",
                dest_ids=None,
                node_id=None):
    obj_x = et.SubElement(archive_element, "object")
    obj_x.set("type", node_type)
    if node_type == "na_link_attribute":
        obj_x.set("uuid", link_node_id)
    else:
        obj_x.set("uuid", node_id)
    a = et.SubElement(obj_x, "attributes")
    pos = et.SubElement(a, "position")
    pos.set("x", str(long))
    pos.set("y", "0.000000")
    pos.set("z", str(lat))
    if node_type == "na_link_attribute":
        a0 = et.SubElement(obj_x, "attributes")
        a0.set("name", "NA_Link_Flow")
        s0 = et.SubElement(a0, "state")
        s0.set("value", "NA_Flow_Forward | NA_Flow_Reverse")

    a1 = et.SubElement(obj_x, "attributes")
    a1.set("name", "NA_Node_Name")
    n_name = et.SubElement(a1, "text")
    n_name.set("value", str(name))
    a2 = et.SubElement(obj_x, "attributes")
    a2.set("name", "NA_Node_Threat")
    s2 = et.SubElement(a2, "scalar")
    s2.set("value", str(threat))
    a3 = et.SubElement(obj_x, "attributes")
    a3.set("name", "NA_Node_Vulnerability")
    s3 = et.SubElement(a3, "scalar")
    s3.set("value", str(vuln))
    a4 = et.SubElement(obj_x, "attributes")
    a4.set("name", "NA_Node_Consequence")
    s4 = et.SubElement(a4, "scalar")
    s4.set("value", str(consequence))
    a5 = et.SubElement(obj_x, "attributes")
    a5.set("name", "NA_Node_Prevention_Cost")
    s5 = et.SubElement(a5, "scalar")
    s5.set("value", str(prevention_cost))
    a6 = et.SubElement(obj_x, "attributes")
    a6.set("name", "NA_Node_Response_Cost")
    s6 = et.SubElement(a6, "scalar")
    s6.set("value", str(response_cost))
    a7 = et.SubElement(obj_x, "attributes")
    a7.set("name", "NA_Node_Description")
    s7 = et.SubElement(a7, "text")
    s7.set("value", str(description))
    a8 = et.SubElement(obj_x, "attributes")
    a8.set("name", "Layer_Link")
    l8 = et.SubElement(a8, "links")
    o8 = et.SubElement(l8, "object")
    o8.set("name", layer_uuid)

    if dest_ids is not None and str(dest_ids) + "1" != "1":
        a10 = et.SubElement(obj_x, "attributes")
        a10.set("name", "Node_Link")
        l10 = et.SubElement(a10, "links")
        ids = str(dest_ids).split("|")
        for i, id in enumerate(ids):
            dest = data.loc[data['node_id'] == id]
            print(id)
            print(dest.longitude.values.item(0))
            midpoint_long = (long + dest.longitude.values.item(0))/2
            midpoint_lat = (lat + dest.latitude.values.item(0))/2
            link_id = str(uuid4())
            create_node(archive_element, layer_uuid,
                        midpoint_long, midpoint_lat, name + "_link_" + str(i), threat="0.380000",
                        vuln="1.000000", consequence="169.75", prevention_cost="870.51",
                        response_cost="10.000000",
                        description="",
                        node_type="na_link_attribute", link_node_id=link_id,
                        dest_ids=None)

            o10 = et.SubElement(l10, "object")
            o10.set("name", id)
            o10.set("attribute", link_id)


root = et.Element("dmz")
a_v = et.SubElement(root, "archive-version")
a_v.set("version", "0")
arch = et.SubElement(root, "archive")
obj_1 = et.SubElement(arch, "object")
obj_1.set("type", "ft_clip_board")
obj_1.set("uuid", "d778c9ed-7d25-4f5f-b11c-7f848b03e7f5")
obj_2 = et.SubElement(arch, "object")
obj_2.set("type", "na_simulator")
obj_2.set("uuid", "1b526352-16bf-6f48-ae94-c34262cc4365")
obj_3 = et.SubElement(arch, "object")
obj_3.set("type", "root_layer")
obj_3.set("uuid", "6c122750-bd5c-42b4-becd-1c1551c97a07")
r_l_attr = et.SubElement(obj_3, "attributes")
r_l_attr.set("name", "Layer_Order")
links = et.SubElement(r_l_attr, "links")
obj_4 = et.SubElement(links, "object")
layer_uuid = "dc22fa13-f7f1-4fac-bc29-942cb3fadc5e"  # str(uuid4())
obj_4.set("name", layer_uuid)
obj_5 = et.SubElement(arch, "object")
obj_5.set("type", "layer")
obj_5.set("uuid", layer_uuid)
l_n = et.SubElement(obj_5, "attributes")
l_n.set("name", "Layer_Name")
n_0 = et.SubElement(l_n, "text")
n_0.set("value", "Network-0")
l_n1 = et.SubElement(obj_5, "attributes")
l_n1.set("name", "Layer_Visible")
n_01 = et.SubElement(l_n1, "flag")
n_01.set("value", "true")
l_n2 = et.SubElement(obj_5, "attributes")
l_n2.set("name", "Layer_Locked")
n_02 = et.SubElement(l_n2, "flag")
n_02.set("value", "false")
l_n3 = et.SubElement(obj_5, "attributes")
l_n3.set("name", "Layer_Active")
n_03 = et.SubElement(l_n3, "flag")
n_03.set("value", "true")

for index, row in data.iterrows():
    # Create nodes for each plant
    create_node(arch, layer_uuid, row.longitude, row.latitude, row["Plant Name"], threat="1.000000",
                vuln="1.000000", consequence=row["Consequence ($M)"], prevention_cost=row["Prevention ($M)"], response_cost=row["Response ($M)"],
                link_node_id=None,
                node_id=row["node_id"],
                dest_ids=row["dest_ids"],
                description=f'Capacity (MW) {row["Capacity (MW)"]} Fuel type {row["Fuel type"]}')

    # <active-channel-list>
    #     <channel name="NetworkAnalysisChannel" />
    # </active-channel-list>
active_ch_list = et.SubElement(root, "active-channel-list")
ch = et.SubElement(active_ch_list, "channel")
ch.set("name", "NetworkAnalysisChannel")
nama_arch = et.SubElement(root, "NAMapArchive")
m_c = et.SubElement(nama_arch, "mapControl")
c = et.SubElement(m_c, "center")
c.set("x", "-97.733330")  # Austin Texas aka the heart of texas
c.set("y", "30.266666")
z = et.SubElement(m_c, "zoom")
z.set("value", "7")
dmz_qt = et.SubElement(root, "dmzQtPluginMapProperties")
s_m = et.SubElement(dmz_qt, "show-map")
s_m.set("value", "true")
m_a = et.SubElement(dmz_qt, "map-adapter")
m_a.set("name", "OpenStreetMap")
m_a.set("type", "tile")
m_a.set("server", "tile.openstreetmap.org")
m_a.set("path", "/%1/%2/%3.png")
m_a.set("tileSize", "256")
m_a.set("minZoom", "0")
m_a.set("maxZoom", "17")


# print(et.tostring(root, xml_declaration=True, pretty_print=True, encoding="utf-8"))
tree = et.ElementTree(root)

tree.write("./src/outputs/mbra.xml", xml_declaration=True,
           pretty_print=True, encoding="utf-8")

# Create a ZipFile Object
with ZipFile('./src/outputs/texas_electric.mbra', 'w') as zipObj2:
    zipObj2.write('./src/outputs/mbra.xml')

# Label it mbra.xml
# Zip it and call zip *.mbra
