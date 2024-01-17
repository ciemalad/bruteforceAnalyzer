--
-- PostgreSQL database dump
--

-- Dumped from database version 16.1
-- Dumped by pg_dump version 16.1

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: ip_addr; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.ip_addr (
    id integer NOT NULL,
    ip_address character varying(45) NOT NULL,
    vt_rep integer,
    vt_vs character varying(10),
    aipdb_s integer
);


ALTER TABLE public.ip_addr OWNER TO postgres;

--
-- Name: ip_addr_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.ip_addr_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.ip_addr_id_seq OWNER TO postgres;

--
-- Name: ip_addr_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.ip_addr_id_seq OWNED BY public.ip_addr.id;


--
-- Name: ip_addr id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ip_addr ALTER COLUMN id SET DEFAULT nextval('public.ip_addr_id_seq'::regclass);


--
-- Data for Name: ip_addr; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.ip_addr (id, ip_address, vt_rep, vt_vs, aipdb_s) FROM stdin;
1	192.168.1.1	1	Yes	50
2	10.0.0.1	3	No	75
3	192.168.0.10	2	0/89	0
\.


--
-- Name: ip_addr_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.ip_addr_id_seq', 3, true);


--
-- Name: ip_addr ip_addr_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ip_addr
    ADD CONSTRAINT ip_addr_pkey PRIMARY KEY (id);


--
-- PostgreSQL database dump complete
--

