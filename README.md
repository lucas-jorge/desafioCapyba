# API RESTful - Desafio Capyba

Esta é uma API RESTful desenvolvida como parte do desafio técnico da Capyba. A API implementa funcionalidades de cadastro, autenticação (via Token), gerenciamento de perfil, confirmação de e-mail, e listagem/criação de itens com recursos avançados como paginação, busca, ordenação e filtros.

## Tecnologias Utilizadas

* **Python** (3.10+)
* **Django**
* **Django REST Framework (DRF)**
* **SQLite** (Banco de dados padrão)
* **django-filter** (Para filtros avançados na API)
* **drf-yasg** (Para geração de documentação OpenAPI/Swagger)
* **Pillow** (Para manipulação de imagens - foto de perfil)

## Pré-requisitos

Antes de começar, garanta que você tem instalado:

* Python (versão 3.10 ou superior recomendada)
* Pip (gerenciador de pacotes Python, geralmente vem com o Python)
* Git (para clonar o repositório)

## Instalação e Configuração

Siga os passos abaixo para configurar o ambiente de desenvolvimento:

1.  **Clone o Repositório:**
    ```bash
    git clone [https://github.com/lucas-jorge/desafioCapyba.git]
    cd nome-da-pasta-do-projeto # Navegue para a pasta criada
    ```

2.  **Crie um Ambiente Virtual:**
    É altamente recomendado usar um ambiente virtual para isolar as dependências do projeto.
    ```bash
    python -m venv venv
    ```
    *(Você pode usar outro nome em vez de `venv` se preferir)*

3.  **Ative o Ambiente Virtual:**
    * No Linux/macOS:
        ```bash
        source venv/bin/activate
        ```
    * No Windows (CMD/PowerShell):
        ```bash
        .\venv\Scripts\activate
        ```

4.  **Instale as Dependências:**
    Instale todas as bibliotecas Python necessárias listadas no arquivo `requirements.txt`.
    ```bash
    pip install -r requirements.txt
    ```

5.  **Aplique as Migrações:**
    Crie as tabelas no banco de dados SQLite com base nos modelos definidos.
    ```bash
    python manage.py migrate
    ```

## Rodando o Projeto

Após a configuração, você pode iniciar o servidor de desenvolvimento do Django:

```bash
python manage.py runserver