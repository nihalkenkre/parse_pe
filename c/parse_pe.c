#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv, char **env)
{
    int ret_val = 0;

    if (argc == 1)
    {
        printf("Usage: parse_pe.exe <filename> <options>\n");
        ret_val = 1;

        goto shutdown;
    }

    if (argc == 2)
    {
        printf("Nothing to print here. Pass -h to list options.\n");
        ret_val = 2;

        goto shutdown;
    }

    char *args[] = {"--dos-header",
                    "--dos-stub",
                    "--nt-headers-signature",
                    "--nt-headers-file-header",
                    "--nt-headers-optional-header",
                    "--section-headers",
                    "--exported-functions",
                    "--imported-functions"};

    if (strcmp(argv[2], "-h") == 0)
    {
        printf("Printing Help\n");
    }
    else if (strcmp(argv[2], "--dos-header") == 0)
    {
        printf("Printing DOS Header\n");
    }
    else if (strcmp(argv[2], "--dos-stub") == 0)
    {
        printf("Printing DOS Stub\n");
    }
    else if (strcmp(argv[2], "--nt-headers-signature") == 0)
    {
        printf("Printing NT headers signature\n");
    }
    else if (strcmp(argv[2], "--nt-headers-file-header") == 0)
    {
        printf("Printing NT headers file header\n");
    }
    else if (strcmp(argv[2], "--nt-headers-optional-header") == 0)
    {
        printf("Printing NT headers optional header\n");
    }
    else if (strcmp(argv[2], "--section-headers") == 0)
    {
        printf("Printing Section headers\n");
    }
    else if (strcmp(argv[2], "--exported-functions") == 0)
    {
        if (argc != 4)
        {
            printf("Please pass the number of exported functions to print\n");
            ret_val = 3;

            goto shutdown;
        }
        int exported_function_count = atoi(argv[3]);
        printf("Printing %d Exported Functions\n", exported_function_count);
    }
    else if (strcmp(argv[2], "--imported-functions") == 0)
    {
        if (argc != 4)
        {
            printf("Please pass the number of imported functions to print\n");
            ret_val = 3;

            goto shutdown;
        }
        int imported_function_count = atoi(argv[3]);
        printf("Printing %d Imported Functions\n", imported_function_count);
    }

shutdown:

    return ret_val;
}