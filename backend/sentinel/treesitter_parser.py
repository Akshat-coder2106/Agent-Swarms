"""Tree-sitter AST parsing for multi-language support."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

import tree_sitter_go as tsgo
import tree_sitter_java as tsjava
import tree_sitter_javascript as tsjavascript
import tree_sitter_python as tspython
import tree_sitter_rust as tsrust
import tree_sitter_typescript as tstypescript
from tree_sitter import Language, Parser

from .models import CodeChunk, CodeGraphEdge, CodeSymbol, sha256_text


class LanguageType(StrEnum):
    """Supported programming languages."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    GO = "go"
    RUST = "rust"
    JAVA = "java"


@dataclass
class ASTNode:
    """AST node representation."""

    node_id: str
    node_type: str
    text: str
    start_line: int
    end_line: int
    start_byte: int
    end_byte: int
    children: list[ASTNode]
    metadata: dict[str, Any]


@dataclass
class ParsedFile:
    """Result of parsing a file."""

    file_path: str
    language: LanguageType
    symbols: list[CodeSymbol]
    edges: list[CodeGraphEdge]
    ast_root: ASTNode
    chunks: list[CodeChunk]


class TreeSitterParser:
    """Multi-language AST parser using Tree-sitter."""

    def __init__(self) -> None:
        self._languages: dict[LanguageType, Language] = {
            LanguageType.PYTHON: Language(tspython.language()),
            LanguageType.JAVASCRIPT: Language(tsjavascript.language()),
            LanguageType.TYPESCRIPT: Language(tstypescript.language_typescript()),
            LanguageType.GO: Language(tsgo.language()),
            LanguageType.RUST: Language(tsrust.language()),
            LanguageType.JAVA: Language(tsjava.language()),
        }
        self._parsers: dict[LanguageType, Parser] = {}

    def _get_parser(self, language: LanguageType) -> Parser:
        """Get or create a parser for the language."""
        if language not in self._parsers:
            parser = Parser()
            parser.set_language(self._languages[language])
            self._parsers[language] = parser
        return self._parsers[language]

    def detect_language(self, file_path: Path) -> LanguageType | None:
        """Detect language from file extension."""
        suffix = file_path.suffix.lower()
        mapping = {
            ".py": LanguageType.PYTHON,
            ".js": LanguageType.JAVASCRIPT,
            ".jsx": LanguageType.JAVASCRIPT,
            ".ts": LanguageType.TYPESCRIPT,
            ".tsx": LanguageType.TYPESCRIPT,
            ".go": LanguageType.GO,
            ".rs": LanguageType.RUST,
            ".java": LanguageType.JAVA,
        }
        return mapping.get(suffix)

    def parse_file(
        self,
        root: Path,
        file_path: Path,
        text: str,
        chunk_size: int = 80,
    ) -> ParsedFile:
        """Parse a source file into AST, symbols, and chunks."""
        language = self.detect_language(file_path)
        if not language:
            raise ValueError(f"Unsupported file type: {file_path}")

        parser = self._get_parser(language)
        tree = parser.parse(bytes(text, "utf-8"))

        # Build AST node tree
        ast_root = self._build_ast_node(tree.root_node, text)

        # Extract symbols
        symbols = self._extract_symbols(language, tree.root_node, root, file_path, text)

        # Extract edges (relationships)
        edges = self._extract_edges(language, tree.root_node, symbols, text)

        # Create chunks
        chunks = self._create_chunks(root, file_path, text, chunk_size)

        return ParsedFile(
            file_path=str(file_path.relative_to(root)),
            language=language,
            symbols=symbols,
            edges=edges,
            ast_root=ast_root,
            chunks=chunks,
        )

    def _build_ast_node(self, node, text: str) -> ASTNode:
        """Recursively build AST node tree."""
        children = [self._build_ast_node(child, text) for child in node.children]
        return ASTNode(
            node_id=self._node_id(node),
            node_type=node.type,
            text=text[node.start_byte : node.end_byte],
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            start_byte=node.start_byte,
            end_byte=node.end_byte,
            children=children,
            metadata={},
        )

    def _node_id(self, node) -> str:
        """Generate unique node ID."""
        return sha256_text(f"{node.type}:{node.start_byte}:{node.end_byte}")

    def _extract_symbols(
        self,
        language: LanguageType,
        root_node,
        root: Path,
        file_path: Path,
        text: str,
    ) -> list[CodeSymbol]:
        """Extract code symbols based on language."""
        if language == LanguageType.PYTHON:
            return self._extract_python_symbols(root_node, root, file_path, text)
        elif language in (LanguageType.JAVASCRIPT, LanguageType.TYPESCRIPT):
            return self._extract_javascript_symbols(root_node, root, file_path, text)
        elif language == LanguageType.GO:
            return self._extract_go_symbols(root_node, root, file_path, text)
        elif language == LanguageType.RUST:
            return self._extract_rust_symbols(root_node, root, file_path, text)
        elif language == LanguageType.JAVA:
            return self._extract_java_symbols(root_node, root, file_path, text)
        return []

    def _extract_python_symbols(
        self,
        root_node,
        root: Path,
        file_path: Path,
        text: str,
    ) -> list[CodeSymbol]:
        """Extract Python symbols (functions, classes, methods)."""
        symbols = []
        relative = str(file_path.relative_to(root))

        def traverse(node, parent_id: str | None = None):
            if node.type in ("function_definition", "async_function_definition"):
                name_node = node.child_by_field_name("name")
                if name_node:
                    name = text[name_node.start_byte : name_node.end_byte]
                    symbol_id = f"sym_{sha256_text(f'{relative}:{name}:{node.start_point[0]}')[:16]}"
                    symbols.append(
                        CodeSymbol(
                            symbol_id=symbol_id,
                            name=name,
                            kind="function",
                            file_path=relative,
                            start_line=node.start_point[0] + 1,
                            end_line=node.end_point[0] + 1,
                        )
                    )
            elif node.type == "class_definition":
                name_node = node.child_by_field_name("name")
                if name_node:
                    name = text[name_node.start_byte : name_node.end_byte]
                    symbol_id = f"sym_{sha256_text(f'{relative}:{name}:{node.start_point[0]}')[:16]}"
                    symbols.append(
                        CodeSymbol(
                            symbol_id=symbol_id,
                            name=name,
                            kind="class",
                            file_path=relative,
                            start_line=node.start_point[0] + 1,
                            end_line=node.end_point[0] + 1,
                        )
                    )

            for child in node.children:
                traverse(child, parent_id)

        traverse(root_node)
        return symbols

    def _extract_javascript_symbols(
        self,
        root_node,
        root: Path,
        file_path: Path,
        text: str,
    ) -> list[CodeSymbol]:
        """Extract JavaScript/TypeScript symbols."""
        symbols = []
        relative = str(file_path.relative_to(root))

        def traverse(node):
            if node.type in ("function_declaration", "function_expression", "arrow_function"):
                name_node = node.child_by_field_name("name")
                if name_node:
                    name = text[name_node.start_byte : name_node.end_byte]
                    symbol_id = f"sym_{sha256_text(f'{relative}:{name}:{node.start_point[0]}')[:16]}"
                    symbols.append(
                        CodeSymbol(
                            symbol_id=symbol_id,
                            name=name,
                            kind="function",
                            file_path=relative,
                            start_line=node.start_point[0] + 1,
                            end_line=node.end_point[0] + 1,
                        )
                    )
            elif node.type == "class_declaration":
                name_node = node.child_by_field_name("name")
                if name_node:
                    name = text[name_node.start_byte : name_node.end_byte]
                    symbol_id = f"sym_{sha256_text(f'{relative}:{name}:{node.start_point[0]}')[:16]}"
                    symbols.append(
                        CodeSymbol(
                            symbol_id=symbol_id,
                            name=name,
                            kind="class",
                            file_path=relative,
                            start_line=node.start_point[0] + 1,
                            end_line=node.end_point[0] + 1,
                        )
                    )

            for child in node.children:
                traverse(child)

        traverse(root_node)
        return symbols

    def _extract_go_symbols(
        self,
        root_node,
        root: Path,
        file_path: Path,
        text: str,
    ) -> list[CodeSymbol]:
        """Extract Go symbols."""
        symbols = []
        relative = str(file_path.relative_to(root))

        def traverse(node):
            if node.type == "function_declaration":
                name_node = node.child_by_field_name("name")
                if name_node:
                    name = text[name_node.start_byte : name_node.end_byte]
                    symbol_id = f"sym_{sha256_text(f'{relative}:{name}:{node.start_point[0]}')[:16]}"
                    symbols.append(
                        CodeSymbol(
                            symbol_id=symbol_id,
                            name=name,
                            kind="function",
                            file_path=relative,
                            start_line=node.start_point[0] + 1,
                            end_line=node.end_point[0] + 1,
                        )
                    )

            for child in node.children:
                traverse(child)

        traverse(root_node)
        return symbols

    def _extract_rust_symbols(
        self,
        root_node,
        root: Path,
        file_path: Path,
        text: str,
    ) -> list[CodeSymbol]:
        """Extract Rust symbols."""
        symbols = []
        relative = str(file_path.relative_to(root))

        def traverse(node):
            if node.type == "function_item":
                name_node = node.child_by_field_name("name")
                if name_node:
                    name = text[name_node.start_byte : name_node.end_byte]
                    symbol_id = f"sym_{sha256_text(f'{relative}:{name}:{node.start_point[0]}')[:16]}"
                    symbols.append(
                        CodeSymbol(
                            symbol_id=symbol_id,
                            name=name,
                            kind="function",
                            file_path=relative,
                            start_line=node.start_point[0] + 1,
                            end_line=node.end_point[0] + 1,
                        )
                    )

            for child in node.children:
                traverse(child)

        traverse(root_node)
        return symbols

    def _extract_java_symbols(
        self,
        root_node,
        root: Path,
        file_path: Path,
        text: str,
    ) -> list[CodeSymbol]:
        """Extract Java symbols."""
        symbols = []
        relative = str(file_path.relative_to(root))

        def traverse(node):
            if node.type == "method_declaration":
                name_node = node.child_by_field_name("name")
                if name_node:
                    name = text[name_node.start_byte : name_node.end_byte]
                    symbol_id = f"sym_{sha256_text(f'{relative}:{name}:{node.start_point[0]}')[:16]}"
                    symbols.append(
                        CodeSymbol(
                            symbol_id=symbol_id,
                            name=name,
                            kind="function",
                            file_path=relative,
                            start_line=node.start_point[0] + 1,
                            end_line=node.end_point[0] + 1,
                        )
                    )
            elif node.type == "class_declaration":
                name_node = node.child_by_field_name("name")
                if name_node:
                    name = text[name_node.start_byte : name_node.end_byte]
                    symbol_id = f"sym_{sha256_text(f'{relative}:{name}:{node.start_point[0]}')[:16]}"
                    symbols.append(
                        CodeSymbol(
                            symbol_id=symbol_id,
                            name=name,
                            kind="class",
                            file_path=relative,
                            start_line=node.start_point[0] + 1,
                            end_line=node.end_point[0] + 1,
                        )
                    )

            for child in node.children:
                traverse(child)

        traverse(root_node)
        return symbols

    def _extract_edges(
        self,
        language: LanguageType,
        root_node,
        symbols: list[CodeSymbol],
        text: str,
    ) -> list[CodeGraphEdge]:
        """Extract call relationships between symbols."""
        edges = []
        symbol_map = {s.name: s.symbol_id for s in symbols}

        def traverse(node):
            if node.type == "call":
                func_node = node.child_by_field_name("function")
                if func_node:
                    func_name = text[func_node.start_byte : func_node.end_byte]
                    if func_name in symbol_map:
                        # Find the containing function
                        parent = node.parent
                        while parent and parent.type not in (
                            "function_definition",
                            "function_declaration",
                            "method_declaration",
                        ):
                            parent = parent.parent
                        if parent:
                            # This is simplified - in practice, you'd need to map parent to symbol
                            pass

            for child in node.children:
                traverse(child)

        traverse(root_node)
        return edges

    def _create_chunks(
        self,
        root: Path,
        file_path: Path,
        text: str,
        chunk_size: int,
    ) -> list[CodeChunk]:
        """Create code chunks from file."""
        lines = text.splitlines()
        chunks = []
        relative = str(file_path.relative_to(root))

        for start in range(0, len(lines), chunk_size):
            end = min(start + chunk_size, len(lines))
            chunk_text = "\n".join(lines[start:end])
            chunk_id = f"chunk_{sha256_text(f'{relative}:{start+1}:{end}')[:16]}"
            chunks.append(
                CodeChunk(
                    chunk_id=chunk_id,
                    file_path=relative,
                    start_line=start + 1,
                    end_line=end,
                    text=chunk_text,
                    token_fingerprint=sha256_text(chunk_text),
                )
            )

        return chunks
