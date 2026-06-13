import json
import logging
import os

import networkx as nx

logger = logging.getLogger("offsploit.ad_exploiter")

class BloodHoundParser:
    """
    Parses BloodHound v4/v5 JSON files into a NetworkX Directed Graph.
    Uses Dijkstra's algorithm to find the shortest attack path between nodes.
    """
    def __init__(self):
        self.graph = nx.DiGraph()
        self.nodes_data = {}

    def load_directory(self, folder_path: str) -> bool:
        """
        Loads all .json files in the given directory.
        """
        if not os.path.isdir(folder_path):
            logger.error(f"Directory not found: {folder_path}")
            return False

        json_files = [f for f in os.listdir(folder_path) if f.endswith(".json")]
        if not json_files:
            logger.error("No JSON files found in the directory.")
            return False

        success_count = 0
        for f in json_files:
            file_path = os.path.join(folder_path, f)
            if self._parse_file(file_path):
                success_count += 1

        logger.info(f"Loaded {success_count} BloodHound files into graph.")
        logger.info(f"Graph size: {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges.")
        return success_count > 0

    def _parse_file(self, file_path: str) -> bool:
        try:
            with open(file_path, encoding="utf-8") as f:
                data = json.load(f)

            # Usually BloodHound JSON has a "data" array
            if "data" not in data:
                return False

            for item in data["data"]:
                # Extract node properties
                node_props = item.get("Properties", {})
                node_name = node_props.get("name", "").upper()
                node_type = node_props.get("domain", "UNKNOWN").upper()

                # Sometime name is just the ID or inside objectId
                if not node_name:
                    node_name = item.get("ObjectIdentifier", "").upper()

                if not node_name:
                    continue

                self.graph.add_node(node_name)
                self.nodes_data[node_name] = item

                # Process relationships (Aces, Links, etc depending on BH version)
                self._parse_edges(node_name, item)

            return True
        except Exception as e:
            logger.error(f"Failed to parse {file_path}: {e}")
            return False

    def _parse_edges(self, source_node: str, item: dict):
        """
        Extracts edges from BloodHound items.
        Handles Aces, AllowedToDelegate, HasSession, etc.
        """
        # Parse Aces (Access Control Entries)
        if "Aces" in item:
            for ace in item["Aces"]:
                target_name = ace.get("PrincipalSID", "").upper()
                # If PrincipalSID is not available, try other fields
                if not target_name:
                    target_name = ace.get("PrincipalName", "").upper()

                right = ace.get("RightName", "UnknownRight")

                if target_name:
                    # In BH, ACE means Principal -> Right -> Target
                    # Here 'item' is the Target, Principal is the Source
                    # But for attack paths, we go Source -> Target
                    # Wait, if item is a Group, and ACE says UserX has GenericAll on Group
                    # Then UserX -> GenericAll -> Group.
                    # So TargetName (UserX) -> item (Group)
                    self.graph.add_edge(target_name, source_node, relation=right)

        # Parse HasSession (Computers -> Users)
        if "Sessions" in item:
            for session in item["Sessions"]:
                user = session.get("UserId", session.get("UserName", "")).upper()
                if user:
                    # Computer -> HasSession -> User
                    # Actually for Attack paths: User has a session on Computer,
                    # If we have Admin on Computer, we can dump User.
                    # Computer -> HasSession -> User
                    self.graph.add_edge(source_node, user, relation="HasSession")

        # Parse MemberOf
        props = item.get("Properties", {})
        if "memberof" in props:
            # Not standard in all BH, usually in Links
            pass

        # Parse Links (Depends on BH version, e.g. for Groups)
        if "Members" in item:
            for member in item["Members"]:
                member_name = member.get("ObjectIdentifier", member.get("MemberName", "")).upper()
                if member_name:
                    # Member -> MemberOf -> Group
                    self.graph.add_edge(member_name, source_node, relation="MemberOf")

        # Parse Local Admins
        if "LocalAdmins" in item:
            for admin in item["LocalAdmins"]:
                admin_name = admin.get("ObjectIdentifier", admin.get("PrincipalName", "")).upper()
                if admin_name:
                    # Admin -> AdminTo -> Computer
                    self.graph.add_edge(admin_name, source_node, relation="AdminTo")

    def find_attack_path(self, start_node: str, end_node: str) -> list[tuple[str, str, str]] | None:
        """
        Finds the shortest path from start_node to end_node.
        Returns a list of (NodeA, Relation, NodeB) tuples.
        """
        start_node = start_node.upper()
        end_node = end_node.upper()

        # Check if nodes exist
        found_start = None
        found_end = None

        # Fuzzy match nodes since exact names might include domain
        for node in self.graph.nodes():
            if start_node in node:
                found_start = node
            if end_node in node:
                found_end = node

        if not found_start:
            logger.error(f"Start node not found matching: {start_node}")
            return None

        if not found_end:
            logger.error(f"End node not found matching: {end_node}")
            return None

        try:
            path = nx.shortest_path(self.graph, source=found_start, target=found_end)

            # Format path into (Source, Relation, Target)
            path_details = []
            for i in range(len(path) - 1):
                source = path[i]
                target = path[i+1]
                edge_data = self.graph.get_edge_data(source, target)
                relation = edge_data.get("relation", "Unknown") if edge_data else "Unknown"
                path_details.append((source, relation, target))

            return path_details

        except nx.NetworkXNoPath:
            logger.error(f"No path found between {found_start} and {found_end}")
            return None
        except Exception as e:
            logger.error(f"Error finding path: {e}")
            return None

    def format_path_for_llm(self, path: list[tuple[str, str, str]]) -> str:
        """
        Formats the attack path into a readable string for the LLM.
        """
        if not path:
            return "No valid path provided."

        output = "Active Directory Attack Path:\n"
        for i, (source, relation, target) in enumerate(path):
            output += f"{i+1}. [{source}] --({relation})--> [{target}]\n"

        return output
